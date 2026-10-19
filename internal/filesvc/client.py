"""In-memory relay client. No persistent helper, credentials or config required."""
import argparse, base64, contextlib, fnmatch, hashlib, io, json, os, pathlib, re, shlex, shutil, subprocess, sys, tarfile, tempfile, uuid, stat

BLOCK = 1024 * 1024

_mux_dir = None

def _mux_options():
    # Every RPC is one ssh invocation; sharing one connection avoids a full
    # handshake (signed through the forwarded agent) per 1 MiB block.
    global _mux_dir
    if os.environ.get('ASSH_NO_MUX') or os.name == 'nt': return []
    if _mux_dir is None:
        import atexit, tempfile
        # Short /tmp path: unix socket paths are limited to about 104 bytes.
        _mux_dir = tempfile.mkdtemp(prefix='assh-', dir='/tmp' if os.path.isdir('/tmp') else None)
        atexit.register(_close_mux)
    return ['-o', 'ControlMaster=auto', '-o', 'ControlPath=' + os.path.join(_mux_dir, 'c'), '-o', 'ControlPersist=60']

def _close_mux():
    base = shlex.split(os.environ.get('ASSH_SSH_COMMAND', ''))
    if base and os.path.exists(os.path.join(_mux_dir, 'c')):
        subprocess.run([base[0], *_mux_options(), '-O', 'exit', *base[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(_mux_dir, ignore_errors=True)

def ssh_args(args):
    encoded = base64.b64encode(b'\0'.join(a.encode('utf-8') for a in args)+b'\0').decode('ascii')
    base = shlex.split(os.environ['ASSH_SSH_COMMAND'])
    # ssh uses the first value of an option, so mux options precede the user's.
    return base[:1] + _mux_options() + base[1:] + ['__assh_rpc_v1 ' + encoded]

# Operations that are safe to repeat. Exit 255 with no output means ssh itself
# failed (connection refused, handshake timeout on a busy tunnel); commit is
# not retried because a lost reply may hide a rename that already happened.
RETRYABLE = {'blocks', 'stat', 'hash', 'ls', 'find', 'mkdir', 'stage', 'write', 'get'}

def rpc(args, data=None, raw=False):
    op = args[1] if args[0] == 'fs' else args[0]
    for attempt in range(4):
        p = subprocess.run(ssh_args(args), input=data, stdout=subprocess.PIPE)
        if p.returncode != 255 or p.stdout or op not in RETRYABLE or attempt == 3: break
        import time; time.sleep(1 + attempt * 2)
    if p.returncode:
        raise RuntimeError('assh file RPC failed (exit %s)' % p.returncode)
    return p.stdout if raw else json.loads(p.stdout)

def hashes(path, block=BLOCK):
    values, total, full = [], 0, hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                b = f.read(block)
                if not b: break
                total += len(b); full.update(b); values.append(hashlib.sha256(b).hexdigest())
    except FileNotFoundError:
        return dict(exists=False, size=0, blocks=[], sha256=hashlib.sha256(b'').hexdigest())
    return dict(exists=True, size=total, blocks=values, sha256=full.hexdigest())

def normalized_chunks(f, size=BLOCK):
    tail = b''
    while True:
        b = f.read(size)
        if not b:
            if tail: yield tail
            return
        b = tail + b; tail = b''
        if b.endswith(b'\r'): b, tail = b[:-1], b'\r'
        yield b.replace(b'\r\n', b'\n')

def put(src, dst, dry=False, text=False):
    if text:
        if dry:
            # Plan normalized blocks without allocating any temporary files.
            full=hashlib.sha256();hs=[];size=0;pending=b'';sizes=[]
            with open(src,'rb') as f:
                for chunk in normalized_chunks(f):
                    pending+=chunk
                    while len(pending)>=BLOCK:
                        b,pending=pending[:BLOCK],pending[BLOCK:]
                        full.update(b);hs.append(hashlib.sha256(b).hexdigest());size+=len(b);sizes.append(len(b))
            if pending:
                full.update(pending);hs.append(hashlib.sha256(pending).hexdigest());size+=len(pending);sizes.append(len(pending))
            remote=rpc(['fs','blocks',dst,'--block-size',str(BLOCK)])
            changed=[i for i,h in enumerate(hs) if i>=len(remote['blocks']) or remote['blocks'][i]!=h]
            return dict(path=dst,dry_run=True,size=size,sha256=full.hexdigest(),changed_blocks=len(changed),transferred_bytes=sum(sizes[i] for i in changed),committed=False)
        # A disk-backed anonymous temporary stream bounds RAM; it is removed on close.
        import tempfile
        with tempfile.TemporaryFile() as tmp, open(src, 'rb') as f:
            for b in normalized_chunks(f): tmp.write(b)
            tmp.seek(0)
            return put_stream(tmp, dst, dry)
    with open(src, 'rb') as f: return put_stream(f, dst, dry)

def put_stream(f, dst, dry):
    transfer=uuid.uuid4().hex
    try:
        return _put_stream(f,dst,dry,transfer)
    finally:
        if not dry:
            try: rpc(['fs','abort',dst,'--transfer-id',transfer])
            except (OSError,RuntimeError): pass

def _put_stream(f, dst, dry, transfer):
    full = hashlib.sha256(); hs = []; size = 0
    while True:
        b = f.read(BLOCK)
        if not b: break
        size += len(b); full.update(b); hs.append(hashlib.sha256(b).hexdigest())
    f.seek(0)
    digest = full.hexdigest()
    if dry:
        # Mirror stage: an identical target needs nothing; otherwise a retained
        # .part from an interrupted run is what the real transfer resumes from.
        remote = rpc(['fs', 'blocks', dst, '--block-size', str(BLOCK)])
        if remote['exists'] and remote['size'] == size and remote['sha256'] == digest:
            remote = dict(unchanged=True)
        else:
            part = rpc(['fs', 'blocks', dst + '.part', '--block-size', str(BLOCK)])
            if part['exists']: remote = part
    else:
        remote = rpc(['fs', 'stage', dst, '--size', str(size), '--block-size', str(BLOCK), '--sha256', digest, '--transfer-id',transfer])
    if remote.get('unchanged'):
        return dict(path=dst, dry_run=dry, size=size, sha256=digest, changed_blocks=0, transferred_bytes=0, committed=not dry, unchanged=True)
    count = transferred = 0
    for i, expected in enumerate(hs):
        b = f.read(BLOCK)
        if i < len(remote['blocks']) and remote['blocks'][i] == expected: continue
        count += 1; transferred += len(b)
        if not dry: rpc(['fs','write',dst,'--offset',str(i*BLOCK),'--size',str(len(b)),'--sha256',expected,'--transfer-id',transfer],b)
    if not dry: rpc(['fs','commit',dst,'--sha256',digest,'--transfer-id',transfer])
    return dict(path=dst, dry_run=dry, size=size, sha256=digest, changed_blocks=count, transferred_bytes=transferred, committed=not dry)

@contextlib.contextmanager
def destination_lock(dst):
    # Locks live outside the destination, so directory transfers cannot
    # accidentally archive their own lock file. OS locks disappear on crash.
    key=hashlib.sha256(os.path.normcase(os.path.realpath(dst)).removesuffix('.part').encode()).hexdigest()
    lockdir=pathlib.Path(tempfile.gettempdir())/'assh-download-locks'
    lockdir.mkdir(mode=0o700,exist_ok=True)
    with os.fdopen(os.open(str(lockdir/(key+'.lock')),os.O_CREAT|os.O_RDWR,0o600),'r+b') as lock:
        if os.name=='nt':
            import msvcrt
            if os.fstat(lock.fileno()).st_size==0: lock.write(b'\0');lock.flush()
            lock.seek(0)
            try: msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
            except OSError: raise RuntimeError('download destination is busy with another transfer')
            try: yield
            finally: lock.seek(0);msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1)
        else:
            import fcntl
            try: fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            except OSError: raise RuntimeError('download destination is busy with another transfer')
            try: yield
            finally: fcntl.flock(lock.fileno(),fcntl.LOCK_UN)

def get(src, dst, dry=False, text=False):
    if dry: return _get(src,dst,dry,text)
    with destination_lock(dst): return _get(src,dst,dry,text)

def download_source(path):
    # Read existing data through a checked handle. Never open a user-controlled
    # staging pathname for writing, even on platforms without O_NOFOLLOW.
    before=os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:
        raise RuntimeError('download source/staging file must be a regular file with one link: '+str(path))
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
    f=os.fdopen(fd,'rb')
    actual=os.fstat(f.fileno())
    if not stat.S_ISREG(actual.st_mode) or actual.st_nlink!=1 or (before.st_dev,before.st_ino)!=(actual.st_dev,actual.st_ino):
        f.close();raise RuntimeError('download source/staging file changed: '+str(path))
    return f


def download_hashes(f,size):
    # Mirror truncate(size) without changing the source during a dry run.
    f.seek(0); values=[];full=hashlib.sha256();remaining=size
    while remaining:
        n=min(BLOCK,remaining);b=f.read(n)
        if len(b)<n: b+=b'\0'*(n-len(b))
        values.append(hashlib.sha256(b).hexdigest());full.update(b);remaining-=n
    return dict(blocks=values,sha256=full.hexdigest())


@contextlib.contextmanager
def download_stage(target, resume=False):
    target=pathlib.Path(target);part=pathlib.Path(str(target)+'.part')
    target.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.assh-download-',dir=target.parent)
    temporary=pathlib.Path(name);f=os.fdopen(fd,'w+b');started=False
    try:
        if resume:
            source=part if os.path.lexists(part) else target
            if os.path.lexists(source):
                with download_source(source) as old: shutil.copyfileobj(old,f,BLOCK)
        started=True
        yield f,temporary
    except BaseException:
        f.close()
        # Replace the pathname itself; never follow a stale .part symlink.
        if started and temporary.exists(): os.replace(temporary,part)
        raise
    finally:
        f.close()
        temporary.unlink(missing_ok=True)


def _get(src, dst, dry=False, text=False):
    remote=rpc(['fs','blocks',src,'--block-size',str(BLOCK)])
    if not remote['exists']: raise FileNotFoundError(src)
    target=pathlib.Path(dst);part=pathlib.Path(str(target)+'.part')
    if target.is_symlink(): raise RuntimeError('download target must not be a symlink: '+str(target))
    def transfer(f,local):
        count=transferred=0
        for i,expected in enumerate(remote['blocks']):
            if i<len(local['blocks']) and local['blocks'][i]==expected: continue
            n=min(BLOCK,remote['size']-i*BLOCK);count+=1;transferred+=n
            if not dry:
                b=rpc(['get',src,'--offset',str(i*BLOCK),'--size',str(n)],raw=True)
                if len(b)!=n or hashlib.sha256(b).hexdigest()!=expected: raise RuntimeError('download chunk SHA256 mismatch; .part retained')
                f.seek(i*BLOCK);f.write(b);f.flush();os.fsync(f.fileno())
        return count,transferred
    if dry:
        source=part if os.path.lexists(part) else target
        if os.path.lexists(source):
            with download_source(source) as old: local=download_hashes(old,remote['size'])
        else: local=download_hashes(io.BytesIO(),remote['size'])
        count,transferred=transfer(None,local)
    else:
        with download_stage(target,True) as (f,temporary):
            f.truncate(remote['size']);local=download_hashes(f,remote['size'])
            count,transferred=transfer(f,local)
            if download_hashes(f,remote['size'])['sha256']!=remote['sha256']: raise RuntimeError('download SHA256 mismatch; .part retained')
            f.flush();os.fsync(f.fileno())
            if text:
                # A random exclusive temporary replaces the old .part.text
                # convention, which could otherwise follow a planted link.
                with download_stage(target) as (normalized,normalized_path):
                    f.seek(0)
                    for b in normalized_chunks(f): normalized.write(b)
                    normalized.flush();os.fsync(normalized.fileno());normalized.close()
                    f.close();os.replace(normalized_path,temporary)
            f.close();os.replace(temporary,target)
            part.unlink(missing_ok=True)
    return dict(path=str(target),dry_run=dry,sha256=remote['sha256'],changed_blocks=count,transferred_bytes=transferred,committed=not dry)

def ignored(rel, directory, patterns):
    result=False
    for pattern in patterns:
        pattern=pattern.rstrip('\r\n')
        # As in git: trailing spaces are dropped unless escaped; \# and \! are literal.
        while pattern.endswith(' ') and not pattern.endswith('\\ '): pattern=pattern[:-1]
        if not pattern.strip() or pattern.startswith('#'): continue
        neg=pattern.startswith('!'); pattern=pattern[1:] if neg else pattern
        anchored=pattern.startswith('/'); pattern=pattern.lstrip('/'); dirs=pattern.endswith('/'); pattern=pattern.rstrip('/')
        expr=''; i=0
        while i<len(pattern):
            c=pattern[i]
            if c=='\\' and i+1<len(pattern):
                expr+=re.escape(pattern[i+1]); i+=2; continue
            if c=='[':
                j=i+1
                if j<len(pattern) and pattern[j] in '!^': j+=1
                if j<len(pattern) and pattern[j]==']': j+=1
                j=pattern.find(']',j)
                if j>0:
                    body=pattern[i+1:j]; negated=body[:1] in ('!','^')
                    if negated: body=body[1:]
                    body=body.replace('\\','\\\\').replace('[','\\[').replace('^','\\^')
                    if body.startswith(']'): body='\\'+body
                    # A class never matches the path separator.
                    expr+=('[^/' if negated else '(?!/)[')+body+']'; i=j+1; continue
            if c=='*':
                if i+1<len(pattern) and pattern[i+1]=='*':
                    i+=1
                    if i+1<len(pattern) and pattern[i+1]=='/': i+=1; expr+='(?:.*/)?'
                    else: expr+='.*'
                else: expr+='[^/]*'
            elif c=='?': expr+='[^/]'
            else: expr+=re.escape(c)
            i+=1
        expr=('^' if anchored or '/' in pattern else '(?:^|/)')+expr+('(?:$|/)' if not dirs or directory else '/')
        if re.search(expr,rel): result=not neg
    return result

def walk(src, patterns):
    for root,dirs,files in os.walk(src,followlinks=False):
        dirs.sort(); files.sort()
        # Do not prune: a later negation may re-include descendants.
        for name in files:
            p=pathlib.Path(root)/name; rel=p.relative_to(src).as_posix()
            if ignored(rel,False,patterns): continue
            if p.is_symlink(): raise RuntimeError('file transfer does not follow symlink: '+str(p))
            yield p,rel

def sync(src,dst,dry=False,text=False,excludes=()):
    if not os.path.isdir(src): raise NotADirectoryError('sync source is not a directory: %s' % src)
    patterns=[]
    ignore=pathlib.Path(src)/'.gitignore'
    if ignore.exists(): patterns+=ignore.read_text(encoding='utf-8').splitlines()
    patterns+=list(excludes)
    if not dry: rpc(['fs','mkdir',dst])
    for root,dirs,_ in os.walk(src,followlinks=False):
        for name in sorted(dirs):
            path=pathlib.Path(root)/name;rel=path.relative_to(src).as_posix()
            if path.is_symlink(): raise RuntimeError('sync does not follow symlinks')
            if not ignored(rel,True,patterns) and not dry: rpc(['fs','mkdir',dst.rstrip('/\\')+'/'+rel])
    results=[]
    for p,rel in walk(pathlib.Path(src),patterns): results.append(put(str(p),dst.rstrip('/\\')+'/'+rel,dry,text))
    return dict(dry_run=dry,files=len(results),changed_blocks=sum(x['changed_blocks'] for x in results),transferred_bytes=sum(x['transferred_bytes'] for x in results),results=results)

def tar_put(src,dst,dry=False,excludes=()):
    if dry: return dict(dry_run=True,operation='put-directory',path=dst,files=[rel for _,rel in walk(pathlib.Path(src),excludes)])
    p=subprocess.Popen(ssh_args(['put',dst,'--tar']),stdin=subprocess.PIPE,stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=p.stdin,mode='w|',format=tarfile.PAX_FORMAT) as archive:
            for root,dirs,_ in os.walk(src):
                for name in sorted(dirs):
                    q=pathlib.Path(root)/name; rel=q.relative_to(src).as_posix()
                    if q.is_symlink(): raise RuntimeError('directory transfer does not follow symlinks')
                    if not ignored(rel,True,excludes): archive.add(q,arcname=rel,recursive=False)
            for q,rel in walk(pathlib.Path(src),excludes):
                info=archive.gettarinfo(str(q),arcname=rel); info.pax_headers={'ASSH.sha256':hashes(q)['sha256']}
                with open(q,'rb') as f: archive.addfile(info,f)
        p.stdin.close(); output=p.stdout.read(); code=p.wait()
        if code: raise RuntimeError('directory upload failed')
        return json.loads(output)
    finally:
        if p.poll() is None: p.kill(); p.wait()

def tar_get(src,dst,dry=False):
    if dry: return _tar_get(src,dst,dry)
    with destination_lock(dst): return _tar_get(src,dst,dry)

def _tar_get(src,dst,dry=False):
    if dry: return dict(dry_run=True,operation='get-directory',source=src,path=dst)
    root=pathlib.Path(dst).resolve();p=subprocess.Popen(ssh_args(['get',src,'--tar']),stdout=subprocess.PIPE)
    count=0
    try:
        with tarfile.open(fileobj=p.stdout,mode='r|') as archive:
            root.mkdir(parents=True,exist_ok=True)
            for member in archive:
                path=root/member.name
                if member.name.startswith('/') or '..' in pathlib.PurePosixPath(member.name).parts or not path.resolve().is_relative_to(root): raise RuntimeError('unsafe tar path')
                if member.isdir(): path.mkdir(parents=True,exist_ok=True); continue
                if not member.isfile(): raise RuntimeError('unsupported tar entry')
                with destination_lock(path):
                    if path.is_symlink(): raise RuntimeError('download target must not be a symlink: '+str(path))
                    with download_stage(path) as (out,temporary):
                        h=hashlib.sha256()
                        with archive.extractfile(member) as inp:
                            while True:
                                b=inp.read(BLOCK)
                                if not b: break
                                out.write(b);h.update(b)
                        out.flush();os.fsync(out.fileno())
                        expected=member.pax_headers.get('ASSH.sha256')
                        if not expected or h.hexdigest()!=expected: raise RuntimeError('tar entry SHA256 mismatch')
                        out.close();os.replace(temporary,path);count+=1
        if p.wait(): raise RuntimeError('directory download failed')
        return dict(path=dst,files=count)
    finally:
        if p.poll() is None: p.kill();p.wait()

def main():
    parser=argparse.ArgumentParser(prog='assh')
    parser.add_argument('command',choices=['put','get','sync']);parser.add_argument('source');parser.add_argument('destination')
    parser.add_argument('--dry-run',action='store_true');parser.add_argument('--text',action='store_true');parser.add_argument('--tar',action='store_true');parser.add_argument('--exclude',action='append',default=[]);parser.add_argument('--json',action='store_true')
    a=parser.parse_args()
    if a.command=='sync': result=sync(a.source,a.destination,a.dry_run,a.text,a.exclude)
    elif a.command=='put':
        if not os.path.exists(a.source): raise FileNotFoundError('source not found: %s' % a.source)
        if a.tar and not os.path.isdir(a.source): raise NotADirectoryError('--tar source is not a directory: %s' % a.source)
        if a.tar or os.path.isdir(a.source):
            if a.text: parser.error('--text is only supported for individual files and sync')
            result=tar_put(a.source,a.destination,a.dry_run,a.exclude)
        else: result=put(a.source,a.destination,a.dry_run,a.text)
    else:
        info=rpc(['fs','stat',a.source])
        if a.tar and not info['directory']: raise NotADirectoryError('--tar source is not a directory: %s' % a.source)
        if a.tar or info['directory']:
            if a.text: parser.error('--text is only supported for individual files and sync')
            result=tar_get(a.source,a.destination,a.dry_run)
        else: result=get(a.source,a.destination,a.dry_run,a.text)
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':
    try: main()
    except (OSError,RuntimeError,ValueError) as e: print('assh: '+str(e),file=sys.stderr);sys.exit(1)
