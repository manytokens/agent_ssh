"""Run inside the Linux relay against the Windows machine through its tunnel."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=22222)
parser.add_argument("--state", default="windows-state")
parser.add_argument("--agent-socket", help="memory-only forwarded agent socket")
args = parser.parse_args()
fixtures = Path("/workspace/work/integration")
private = Path(tempfile.mkdtemp(prefix="assh-agent-"))
shutil.copyfile(fixtures / "agent", private / "key")
os.chmod(private / "key", 0o600)
host_key = (fixtures / args.state / "host_ed25519.pub").read_text().strip()
(private / "known_hosts").write_text(f"[127.0.0.1]:{args.port} {host_key}\n")
common = ["-i", str(private / "key"), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={private / 'known_hosts'}", "-o", "ConnectTimeout=5"]
target = "agent@127.0.0.1"
if args.agent_socket:
    os.environ["SSH_AUTH_SOCK"] = args.agent_socket
    common = ["-F", "none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
              "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
              "-o", "UpdateHostKeys=no", "-o", f"KnownHostsCommand=/bin/echo [127.0.0.1]:{args.port} {host_key}",
              "-o", "ConnectTimeout=5"]
    result = subprocess.run(["ssh-add", "-L"], capture_output=True, timeout=5, check=True)
    assert len(result.stdout.decode().strip().splitlines()) == 1, "forwarded unrelated user identities"
    assert "assh ephemeral reverse access" in result.stdout.decode()
    wrong_key = (fixtures / "agent.pub").read_text().strip()
    bad = [arg if not arg.startswith("KnownHostsCommand=") else f"KnownHostsCommand=/bin/echo [127.0.0.1]:{args.port} {wrong_key}" for arg in common]
    result = subprocess.run(["ssh", *bad, "-p", str(args.port), target, "exit 0"], capture_output=True, timeout=10)
    assert result.returncode != 0 and b"Host key verification failed" in result.stderr, result.stderr
    print("PASS strict fileless host verification rejects wrong host key", flush=True)
ssh = ["ssh", *common, "-p", str(args.port)]


def run(command, expected=0, stdin=None):
    result = subprocess.run([*ssh, target, command], input=stdin, capture_output=True, timeout=20)
    assert result.returncode == expected, (command, result.returncode, result.stdout, result.stderr)
    return result.stdout.decode("utf-8")


def check(label, fn):
    fn()
    print(f"PASS {label}", flush=True)


def commands():
    assert run("[Console]::Write('你好 agent_ssh')") == "你好 agent_ssh"
    run("exit 7", expected=7)
    run("& cmd.exe /d /c 'exit 9'", expected=9)
    run("Write-Error 'expected-error'", expected=1)
    assert run("[Console]::Write([Console]::In.ReadToEnd())", stdin="输入 stdin\n".encode()) == "输入 stdin\n"
    assert "中文 空格" in run("$p=Join-Path (Get-Location) '中文 空格'; New-Item -ItemType Directory -Force -Path $p | Out-Null; [Console]::Write($p)")


def files():
    payload = bytes(range(256)) * 8192
    source, result = private / "payload.bin", private / "download.bin"
    source.write_bytes(payload)
    scp = ["scp", *common, "-P", str(args.port)]
    remote = target + ":中文 空格/二进制 file.bin"
    subprocess.run([*scp, str(source), remote], check=True, timeout=25, capture_output=True)
    subprocess.run([*scp, remote, str(result)], check=True, timeout=25, capture_output=True)
    assert hashlib.sha256(result.read_bytes()).digest() == hashlib.sha256(payload).digest()
    run("Remove-Item -LiteralPath '中文 空格' -Recurse -Force")


def absolute_paths_and_sftp_exit():
    base = run("[Console]::Write((Get-Location).Path.Replace([char]92,[char]47))")
    payload = private / "absolute-source.bin"
    payload.write_bytes(bytes(range(256)) * 4096)
    # The upstream SFTP server takes Windows drives as /D:/... (asscp rewrites
    # D:/... to that form; raw scp/sftp callers write it themselves).
    for prefix in ("/" + base, "/" + base[0].lower() + base[1:]):
        remote_path = prefix + "/绝对 路径.bin"
        scp = ["scp", *common, "-P", str(args.port)]
        remote = target + ":" + remote_path
        dest = private / "absolute-copy.bin"
        subprocess.run([*scp, str(payload), remote], capture_output=True, check=True, timeout=20)
        subprocess.run([*scp, remote, str(dest)], capture_output=True, check=True, timeout=20)
        assert dest.read_bytes() == payload.read_bytes()
        # Explicit bye, EOF without bye, and documented batch mode must all exit.
        for mode in ("bye", "eof", "batch"):
            dest.unlink()
            script = f'pwd\nput "{payload}" "{remote_path}"\nget "{remote_path}" "{dest}"\nrm "{remote_path}"\n'
            if mode == "bye":
                script += "bye\n"
            sftp = ["sftp", *common, "-P", str(args.port)]
            if mode == "batch":
                script = f'put "{payload}" "{remote_path}"\nrename "{remote_path}" "{remote_path}.renamed"\nget "{remote_path}.renamed" "{dest}"\nrm "{remote_path}.renamed"\n'
                sftp += ["-b", "-"]
            result = subprocess.run([*sftp, target], input=script.encode(), capture_output=True, timeout=20)
            assert result.returncode == 0, (mode, prefix, result.stdout, result.stderr)
            assert dest.read_bytes() == payload.read_bytes()
    result = subprocess.run(["sftp", *common, "-P", str(args.port), "-b", "-", target],
                            input=b'get "assh-nonexistent-file"\n', capture_output=True, timeout=10)
    assert result.returncode != 0, "SFTP batch ignored transfer error"


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def forwarding():
    # An inner SSH -R binds on Windows and forwards back to the Linux agent.
    echo = socket.socket()
    echo.bind(("127.0.0.1", 0))
    echo.listen()
    echo.settimeout(15)

    def echo_once():
        with echo:
            conn, _ = echo.accept()
            with conn:
                conn.sendall(conn.recv(128))

    thread = threading.Thread(target=echo_once, daemon=True)
    thread.start()
    remote_port = int(run("$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0); $l.Start(); [Console]::Write($l.LocalEndpoint.Port); $l.Stop()"))
    forward = subprocess.Popen([*ssh, "-N", "-o", "ExitOnForwardFailure=yes", "-R", f"127.0.0.1:{remote_port}:127.0.0.1:{echo.getsockname()[1]}", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    local_port = port()
    local = subprocess.Popen([*ssh, "-N", "-o", "ExitOnForwardFailure=yes", "-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(1)
        assert forward.poll() is None, forward.communicate()
        assert local.poll() is None, local.communicate()
        with socket.create_connection(("127.0.0.1", local_port), timeout=5) as c:
            c.sendall(b"nested-forward-roundtrip")
            assert c.recv(128) == b"nested-forward-roundtrip"
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        for process in (local, forward):
            process.terminate()
            process.wait(timeout=5)
    # The -R listener belongs to the inner connection and must be released.
    time.sleep(0.3)
    assert run(f"$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,{remote_port}); $l.Start(); $l.Stop(); [Console]::Write('released')") == "released"


try:
    check("PowerShell UTF-8, exit status, errors, stdin and space paths", commands)
    check("OpenSSH SCP/SFTP 2 MiB binary roundtrip with Chinese/space paths", files)
    check("Windows absolute SCP/SFTP paths, rename/remove, bye, EOF, batch exit and failure status", absolute_paths_and_sftp_exit)
    check("inner SSH -L/-R nested roundtrip and mapping cleanup", forwarding)
finally:
    shutil.rmtree(private)
