package filesvc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRPCBridge(t *testing.T) {
	if os.Getenv("ASSH_FILE_TEST_BRIDGE") != "1" {
		return
	}
	arg := os.Args[len(os.Args)-1]
	decoded, e := base64.StdEncoding.DecodeString(arg)
	if e != nil {
		os.Exit(2)
	}
	argv := strings.Split(strings.TrimSuffix(string(decoded), "\x00"), "\x00")
	data, _ := io.ReadAll(os.Stdin)
	body, _ := json.Marshal(struct {
		Args []string
		Data []byte
	}{argv, data})
	response, e := http.Post(os.Getenv("ASSH_FILE_TEST_URL"), "application/json", bytes.NewReader(body))
	if e == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			io.Copy(os.Stderr, response.Body)
			os.Exit(1)
		}
		_, e = io.Copy(os.Stdout, response.Body)
	}
	if e != nil {
		os.Stderr.WriteString(e.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func TestPythonDownloadSafetyAndResumePlan(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Skip("python unavailable")
	}
	dir := t.TempDir()
	client := filepath.Join(dir, "client.py")
	if err := os.WriteFile(client, []byte(ClientScript), 0600); err != nil {
		t.Fatal(err)
	}
	const script = `
import importlib.util, pathlib, tempfile, os, io, hashlib, tarfile
spec=importlib.util.spec_from_file_location('client',os.environ['ASSH_QA_CLIENT'])
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
with tempfile.TemporaryDirectory() as tmp:
    root=pathlib.Path(tmp);target=root/'download';part=root/'download.part'
    data=b'new';digest=hashlib.sha256(data).hexdigest()
    def rpc(args,data_arg=None,raw=False):
        if args[:2]==['fs','blocks']:return dict(exists=True,size=len(data),blocks=[digest],sha256=digest)
        return data
    c.rpc=rpc
    for existing in [b'new',b'new trailing',b'n',b'bad']:
        target.write_bytes(b'old');part.write_bytes(existing)
        before=part.read_bytes();plan=c.get('remote',str(target),True)
        assert part.read_bytes()==before
        actual=c.get('remote',str(target))
        assert plan['changed_blocks']==actual['changed_blocks'],(existing,plan,actual)
        assert target.read_bytes()==data
    # Interrupted downloads retain staging bytes without changing the target.
    target.write_bytes(b'old')
    def broken_rpc(args,data_arg=None,raw=False):
        return rpc(args,data_arg,raw) if args[:2]==['fs','blocks'] else b'bad'
    c.rpc=broken_rpc
    try:c.get('remote',str(target))
    except RuntimeError:pass
    else:raise AssertionError('corrupt download accepted')
    assert target.read_bytes()==b'old' and part.exists()
    c.rpc=rpc;c.get('remote',str(target));assert target.read_bytes()==data
    victim=root/'victim';victim.write_bytes(b'precious')
    os.link(victim,part)
    try:c.get('remote',str(target))
    except RuntimeError:pass
    else:raise AssertionError('hardlinked part accepted')
    assert victim.read_bytes()==b'precious';part.unlink()
    legacy=root/'download.part.text';os.link(victim,legacy)
    c.get('remote',str(target),text=True)
    assert victim.read_bytes()==b'precious';legacy.unlink()
    try:os.symlink(victim,part)
    except OSError:pass
    else:
        try:c.get('remote',str(target))
        except RuntimeError:pass
        else:raise AssertionError('symlink part accepted')
        assert victim.read_bytes()==b'precious';part.unlink()
        target.unlink();os.symlink(victim,target)
        try:c.get('remote',str(target))
        except RuntimeError:pass
        else:raise AssertionError('symlink target accepted')
        assert victim.read_bytes()==b'precious';target.unlink()
    tree=root/'tree';tree.mkdir();os.link(victim,tree/'entry.part')
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w') as tar:
        info=tarfile.TarInfo('entry');info.size=len(data);info.pax_headers={'ASSH.sha256':digest}
        tar.addfile(info,io.BytesIO(data))
    class Process:
        def __init__(self):self.stdout=io.BytesIO(archive.getvalue())
        def wait(self):return 0
        def poll(self):return 0
    c.ssh_args=lambda args:args;c.subprocess.Popen=lambda *a,**k:Process()
    c.tar_get('remote',str(tree))
    assert (tree/'entry').read_bytes()==data and victim.read_bytes()==b'precious'
    assert not list(root.rglob('.assh-download-*'))
print('SAFE_DOWNLOAD_OK')
`
	cmd := exec.Command(python, "-c", script)
	cmd.Env = append(os.Environ(), "ASSH_QA_CLIENT="+client)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python download safety: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("SAFE_DOWNLOAD_OK")) {
		t.Fatal(string(output))
	}
}

func TestPythonClientRealRoundtrip(t *testing.T) {
	python, e := exec.LookPath("python3")
	if e != nil {
		python, e = exec.LookPath("python")
	}
	if e != nil {
		t.Skip("python3 not installed")
	}
	exe, _ := os.Executable()
	dir := t.TempDir()
	svc := New(dir)
	defer svc.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Args []string
			Data []byte
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		var out bytes.Buffer
		if err := svc.Handle(r.Context(), request.Args, bytes.NewReader(request.Data), &out, io.Discard); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Write(out.Bytes())
	}))
	defer server.Close()
	client := filepath.Join(dir, "client.py")
	if e := os.WriteFile(client, []byte(ClientScript), 0600); e != nil {
		t.Fatal(e)
	}
	const harness = `
import base64, importlib.util, json, os, pathlib, subprocess, tempfile
spec=importlib.util.spec_from_file_location('assh_client',os.environ['ASSH_FILE_CLIENT_PATH'])
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
def rpc(args,data=None,raw=False):
    encoded=base64.b64encode(b'\0'.join(a.encode() for a in args)+b'\0').decode()
    p=subprocess.run([os.environ['ASSH_FILE_TEST_EXE'],'-test.run=^TestRPCBridge$','--',encoded],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if p.returncode: raise RuntimeError(p.stderr.decode())
    return p.stdout if raw else json.loads(p.stdout)
c.rpc=rpc
# Ignore rules: character classes, escapes and escaped trailing spaces.
for rel,pats,want in [('a.cfg',['[ab].cfg'],True),('c.cfg',['[ab].cfg'],False),('x.pyc',['*.py[co]'],True),('x.py',['*.py[co]'],False),('#n',['\\#n'],True),('#n',['#n'],False),('bx',['[!a]x'],True),('ax',['[!a]x'],False),('t ',['t\\ '],True),('t',['t   '],True),('a/b',['a[/]b'],False)]:
    assert c.ignored(rel,False,pats)==want,(rel,pats)
# Exercise argv framing independently of the bridge.
os.environ['ASSH_SSH_COMMAND']='ssh -p 1234 agent@127.0.0.1'
assert base64.b64decode(c.ssh_args(['get','a b',''])[-1].split()[-1])==b'get\0a b\0\0'
def bridge_args(args):
    encoded=base64.b64encode(b'\0'.join(a.encode() for a in args)+b'\0').decode()
    return [os.environ['ASSH_FILE_TEST_EXE'],'-test.run=^TestRPCBridge$','--',encoded]
c.ssh_args=bridge_args
root=pathlib.Path(os.environ['ASSH_FILE_TEST_WORKDIR']);relay=root/'relay';relay.mkdir()
data=b'a'*c.BLOCK+b'b'*c.BLOCK+b'\x00\xfftail';src=relay/'中文.bin';src.write_bytes(data)
plan=c.put(str(src),'remote/data.bin',True);assert plan['changed_blocks']==3 and not (root/'remote').exists()
first=c.put(str(src),'remote/data.bin');assert first['changed_blocks']==3
assert c.put(str(src),'remote/data.bin')['transferred_bytes']==0
data=data[:c.BLOCK]+b'c'*c.BLOCK+data[c.BLOCK*2:];src.write_bytes(data)
assert c.put(str(src),'remote/data.bin')['changed_blocks']==1
# An identical target is neither copied nor renamed, and a stale .part goes.
target=root/'remote/data.bin';before=target.stat().st_mtime_ns
stale=root/'remote/data.bin.part';stale.write_bytes(b'stale')
same=c.put(str(src),'remote/data.bin');assert same['unchanged'] and same['transferred_bytes']==0
assert target.stat().st_mtime_ns==before and not stale.exists()
assert c.put(str(src),'remote/data.bin',True)['changed_blocks']==0
# Corrupt interrupted part; actual per-block hashes force only the bad block back.
data=data[:c.BLOCK*2]+b'\x01\xfetail2';src.write_bytes(data)
part=root/'remote/data.bin.part';part.write_bytes(b'z'*c.BLOCK+data[c.BLOCK:])
# The plan resumes from the retained part, as the real transfer does.
assert c.put(str(src),'remote/data.bin',True)['changed_blocks']==1
assert c.put(str(src),'remote/data.bin')['changed_blocks']==1
assert target.read_bytes()==data
download=relay/'download.bin';assert c.get('remote/data.bin',str(download))['changed_blocks']==3
assert download.read_bytes()==data
assert c.get('remote/data.bin',str(download))['transferred_bytes']==0
part=pathlib.Path(str(download)+'.part');part.write_bytes(data[:c.BLOCK]+b'x'*c.BLOCK+data[c.BLOCK*2:])
assert c.get('remote/data.bin',str(download))['changed_blocks']==1
text=relay/'text';text.write_bytes('中文\r\na\r\n'.encode())
import tempfile
original_tempfile=tempfile.TemporaryFile
def forbidden_tempfile(*args,**kwargs): raise RuntimeError('dry-run allocated a temporary file')
tempfile.TemporaryFile=forbidden_tempfile
assert c.put(str(text),'remote/dry-text',dry=True,text=True)['sha256']==c.hashlib.sha256('中文\na\n'.encode()).hexdigest()
assert not (root/'remote/dry-text').exists()
tempfile.TemporaryFile=original_tempfile
c.put(str(text),'remote/text',text=True);assert (root/'remote/text').read_bytes()=='中文\na\n'.encode()
c.get('remote/text',str(relay/'normalized'),text=True)
tree=relay/'tree';(tree/'build').mkdir(parents=True);(tree/'build'/'omit').write_text('omit');(tree/'keep').write_bytes(data)
(tree/'.gitignore').write_text('build/\n')
sync=c.sync(str(tree),'synced',True);assert not (root/'synced').exists()
c.sync(str(tree),'synced');assert not (root/'synced/build').exists()
assert c.sync(str(tree),'synced')['transferred_bytes']==0
(tree/'empty').mkdir()
c.tar_put(str(tree),'tar-upload')
c.tar_get('tar-upload',str(relay/'tar-download'))
assert (relay/'tar-download/keep').read_bytes()==data
assert (relay/'tar-download/empty').is_dir()
assert c.tar_put(str(tree),'drytar',True)['dry_run'] and not (root/'drytar').exists()
empty=relay/'empty-root';empty.mkdir()
c.tar_put(str(empty),'empty-upload')
assert (root/'empty-upload').is_dir()
assert c.tar_get('empty-upload',str(relay/'empty-download'))['files']==0
assert (relay/'empty-download').is_dir()
c.tar_get('empty-upload',str(relay/'dry-empty-download'),True)
assert not (relay/'dry-empty-download').exists()
# CLI --tar must reject a regular source before touching the destination,
# including dry-run, instead of accepting an empty archive.
for flags in [[],['--dry-run']]:
    original_argv=c.sys.argv
    c.sys.argv=['assh','get','remote/data.bin',str(relay/'invalid-tar'), '--tar',*flags]
    try:
        try: c.main()
        except NotADirectoryError: pass
        else: raise AssertionError('get --tar accepted a regular file')
    finally: c.sys.argv=original_argv
    assert not (relay/'invalid-tar').exists()
# A second download cannot overwrite the first download's staging bytes.
with c.destination_lock(download):
    try: c.get('remote/data.bin',str(download))
    except RuntimeError as e: assert 'busy' in str(e)
    else: raise AssertionError('download lock was bypassed')
# Directory extraction and individual downloads use the same member locks.
with c.destination_lock(relay/'locked-tree'/'keep'):
    try: c.tar_get('tar-upload',str(relay/'locked-tree'))
    except RuntimeError as e: assert 'busy' in str(e)
    else: raise AssertionError('directory extraction bypassed file lock')
print('PYTHON_TRANSFER_OK')
`
	cmd := exec.Command(python, "-c", harness)
	cmd.Env = append(os.Environ(), "ASSH_FILE_TEST_BRIDGE=1", "ASSH_FILE_TEST_EXE="+exe, "ASSH_FILE_TEST_WORKDIR="+dir, "ASSH_FILE_CLIENT_PATH="+client, "ASSH_FILE_TEST_URL="+server.URL)
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("Python transfer integration: %v\n%s", e, output)
	}
	if !bytes.Contains(output, []byte("PYTHON_TRANSFER_OK")) {
		t.Fatal(string(output))
	}
}
