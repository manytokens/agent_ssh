"""Run inside initialized relay Bash; tests only unique temporary business files."""
import base64
import hashlib
import json
import os
import pathlib
import selectors
import shlex
import subprocess
import tempfile
import time
import uuid


def argv(args):
    payload = base64.b64encode(b"\0".join(a.encode("utf-8") for a in args) + b"\0").decode("ascii")
    return [*shlex.split(os.environ["ASSH_SSH_COMMAND"]), "__assh_rpc_v1 " + payload]


def rpc(args, data=None, raw=False, allow_error=False):
    result = subprocess.run(argv(args), input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
    if allow_error:
        return result
    assert result.returncode == 0, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout if raw else json.loads(result.stdout)


def literal(path):
    return "'" + path.replace("'", "''") + "'" if windows else shlex.quote(path)


def run(script):
    return rpc(["run", "--json", script])["stdout"]


def line(process, timeout=15):
    # Use os.read rather than buffered readline so a missing line has a deadline.
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while b"\n" not in data:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and selector.select(remaining), ("watch output timeout", data)
            chunk = os.read(process.stdout.fileno(), 65536)
            assert chunk, ("watch unexpectedly ended", process.poll(), data)
            data.extend(chunk)
        return json.loads(data.split(b"\n", 1)[0])
    finally:
        selector.close()


windows = os.environ.get("ASSH_TARGET_OS") == "windows"
namespace = {"__name__": "assh_embedded_client"}
exec(compile(os.environ["ASSH_FILE_CLIENT"], "<assh-file-client>", "exec"), namespace)
# All client operations still traverse native OpenSSH and the reserved RPC.
namespace["rpc"] = rpc
target = None
watch = None
try:
    if windows:
        temp = run("[Console]::Write([IO.Path]::GetTempPath())").strip()
    else:
        temp = run("printf '%s' \"${TMPDIR:-/tmp}\"").strip()
    assert temp, "target temporary directory unavailable"
    target = temp.replace("\\", "/").rstrip("/") + "/assh-files-" + uuid.uuid4().hex
    rpc(["fs", "mkdir", target])
    with tempfile.TemporaryDirectory(prefix="assh-relay-files-") as scratch:
        relay = pathlib.Path(scratch)
        source = relay / "中文 source.bin"
        block = namespace["BLOCK"]
        data = bytes(range(256)) * (block // 256) + b"b" * block + b"\x00\xfftail"
        source.write_bytes(data)
        dest = target + "/数据.bin"
        plan = namespace["put"](str(source), dest, dry=True)
        assert plan["changed_blocks"] == 3 and plan["dry_run"], plan
        assert rpc(["fs", "ls", target]) == [], "dry-run created destination or part"
        uploaded = namespace["put"](str(source), dest)
        assert uploaded["changed_blocks"] == 3, uploaded
        assert rpc(["fs", "hash", dest])["sha256"] == hashlib.sha256(data).hexdigest()
        assert namespace["put"](str(source), dest)["transferred_bytes"] == 0
        changed = data[:block] + b"c" * block + data[block * 2:]
        source.write_bytes(changed)
        assert namespace["put"](str(source), dest)["changed_blocks"] == 1

        # An identical target is skipped and a stale .part removed.
        rpc(["put", dest + ".part"], b"stale")
        assert namespace["put"](str(source), dest)["unchanged"]
        assert all(row["name"] != "数据.bin.part" for row in rpc(["fs", "ls", target])), "stale part kept"
        # Simulate an interrupted upload of a newer source: one corrupt staged block, two good ones.
        newer = changed[:block * 2] + b"d" * (len(changed) - block * 2)
        source.write_bytes(newer)
        corrupt = b"z" * block + newer[block:]
        rpc(["put", dest + ".part"], corrupt)
        resumed = namespace["put"](str(source), dest)
        assert resumed["changed_blocks"] == 1 and resumed["transferred_bytes"] == block, resumed
        changed = newer
        bad = rpc(["fs", "write", dest, "--offset", "0", "--size", "1", "--sha256", "0" * 64], b"x", allow_error=True)
        assert bad.returncode != 0, "bad chunk hash accepted"

        download = relay / "download.bin"
        assert namespace["get"](dest, str(download), dry=True)["dry_run"]
        assert not download.exists() and not pathlib.Path(str(download) + ".part").exists()
        namespace["get"](dest, str(download))
        assert download.read_bytes() == changed
        pathlib.Path(str(download) + ".part").write_bytes(changed[:block] + b"x" * block + changed[block * 2:])
        assert namespace["get"](dest, str(download))["changed_blocks"] == 1
        assert download.read_bytes() == changed
        text = relay / "text.txt"
        text.write_bytes("中文\r\na\r\n".encode())
        namespace["put"](str(text), target + "/text.txt", text=True)
        assert rpc(["get", target + "/text.txt"], raw=True) == "中文\na\n".encode()

        tree = relay / "tree"
        (tree / "build").mkdir(parents=True)
        (tree / "empty").mkdir()
        (tree / "build" / "omit.tmp").write_text("omit")
        (tree / "build" / "include.txt").write_text("keep")
        (tree / ".gitignore").write_text("build/\n")
        (tree / "large.bin").write_bytes(changed)
        sync_dest = target + "/synced"
        namespace["sync"](str(tree), sync_dest, dry=True, excludes=["!build/include.txt"])
        assert all(x["name"] != "synced" for x in rpc(["fs", "ls", target]))
        namespace["sync"](str(tree), sync_dest, excludes=["!build/include.txt"])
        found = rpc(["fs", "find", sync_dest])
        assert any(x["path"].replace("\\", "/").endswith("/empty") for x in found)
        assert not any(x["name"] == "omit.tmp" for x in found)
        assert any(x["name"] == "include.txt" for x in found)
        assert namespace["sync"](str(tree), sync_dest, excludes=["!build/include.txt"])["transferred_bytes"] == 0
        next_data = changed[:block] + b"d" * block + changed[block * 2:]
        (tree / "large.bin").write_bytes(next_data)
        incremental = namespace["sync"](str(tree), sync_dest, excludes=["!build/include.txt"])
        assert incremental["changed_blocks"] == 1 and incremental["transferred_bytes"] == block, incremental
        namespace["tar_put"](str(tree), target + "/tarred")
        namespace["tar_get"](target + "/tarred", str(relay / "untarred"))
        assert (relay / "untarred" / "large.bin").read_bytes() == next_data
        assert (relay / "untarred" / "empty").is_dir()

        watched = target + "/watched"
        rpc(["fs", "mkdir", watched + "/child"])
        dry_watch = rpc(["watch", watched, "--dry-run"])
        assert dry_watch["dry_run"] and dry_watch["operation"] == "watch"
        watch = subprocess.Popen(argv(["watch", watched]), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert line(watch)["event"] == "ready"
        rpc(["put", watched + "/child/event.txt"], b"watch")
        event = line(watch)
        assert "/child/" in event["path"].replace("\\", "/"), event
        watch.terminate()
        watch.wait(timeout=10)
        watch.stdout.close(); watch.stderr.close(); watch = None
        # The canceled channel must not poison the shared sshd service.
        assert rpc(["ping"])["pong"]
finally:
    if watch is not None:
        watch.kill(); watch.wait(timeout=10)
        watch.stdout.close(); watch.stderr.close()
    if target:
        cleanup = "Remove-Item -LiteralPath " + literal(target) + " -Recurse -Force" if windows else "rm -rf -- " + literal(target)
        run(cleanup)

print("ASSH_FILES_OK", flush=True)
