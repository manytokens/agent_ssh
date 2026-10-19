"""Run on the disposable relay inside an assh-initialized Bash login.

Uses the reserved argv RPC, never shell-concatenates user command text.
"""
import base64
import json
import os
import shlex
import subprocess
import time
import uuid

prefix = shlex.split(os.environ["ASSH_SSH_COMMAND"])
is_windows = os.environ.get("ASSH_TARGET_OS", "").lower() == "windows"


def rpc(*args, stdin=b"", pty=False, expected=0, timeout=30):
    payload = b"".join(str(a).encode("utf-8") + b"\0" for a in args)
    command = "__assh_rpc_v1 " + base64.b64encode(payload).decode("ascii")
    argv = prefix[:1] + (["-tt"] if pty else []) + prefix[1:] + [command]
    p = subprocess.run(argv, input=stdin, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    if expected is not None:
        assert p.returncode == expected, (args, p.returncode, p.stdout, p.stderr)
    return p


def result(*args, expected=0):
    p = rpc(*args, expected=expected)
    return json.loads(p.stdout)


def read_until(session, needle, offset=0):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        m = result("session", "read", session, "--offset", str(offset), "--wait", "200ms")
        if needle in m["stdout"]:
            return m
    raise AssertionError(("session output timeout", needle, m))


script = ("[Console]::Write('中文'); [Console]::Error.Write('stderr-only'); exit 7"
          if is_windows else "printf '中文'; printf stderr-only >&2; exit 7")
m = result("run", "--json", script, expected=7)
assert m["stdout"] == "中文" and m["stderr"] == "stderr-only", m
assert m["exit_code"] == 7, m
slow = "Start-Sleep 30" if is_windows else "sleep 30"
m = result("run", "--json", "--timeout", "0.2", slow, expected=124)
assert m["timed_out"] is True and m["duration"] < 5, m

# Dry-run returns the actual planned executable arguments and never runs scripts.
dry = result("run", "--dry-run", "exit 99")
assert dry["dry_run"] and dry["argv"], dry

session = result("session", "new")["id"]
try:
    if is_windows:
        setup = ("$env:ASSH_RPC_PERSIST='persisted'; Set-Location $env:TEMP; "
                 "New-Module -Name ASSHRpcPersist -ScriptBlock { "
                 "function Get-ASSHRpcPersist { 'MODULE_STATE_OK' }; "
                 "Export-ModuleMember -Function Get-ASSHRpcPersist } | Import-Module; "
                 "Write-Output ('SETUP_'+'DONE')")
        query = "Write-Output $env:ASSH_RPC_PERSIST; Get-Location; Get-ASSHRpcPersist"
    else:
        setup = "export ASSH_RPC_PERSIST=persisted; cd /tmp; assh_rpc_func() { printf MODULE_STATE_OK; }; printf SETUP_DONE"
        query = "printf '%s\\n' \"$ASSH_RPC_PERSIST\"; pwd; assh_rpc_func"
    result("session", "send", session, setup)
    m = read_until(session, "SETUP_DONE")
    offset = m["offset"]
    result("session", "send", session, query)
    m = read_until(session, "MODULE_STATE_OK", offset)
    assert "persisted" in m["stdout"], m
    result("session", "close", session, "--dry-run")
    assert result("session", "read", session)["running"] is True
finally:
    result("session", "close", session)

job_script = ("Start-Sleep -Milliseconds 300; Write-Output JOB_SURVIVED"
              if is_windows else "sleep 0.3; printf JOB_SURVIVED")
job = result("job", "start", job_script)["id"]
result("job", "kill", job, "--dry-run")
m = result("job", "wait", job)
assert "JOB_SURVIVED" in m["stdout"] and m["exit_code"] == 0, m
assert m["truncated"] is False, m

# Real terminal output and resize/lifetime are also covered by native Go tests.
pty_script = "Write-Output PTY_RPC_OK" if is_windows else "printf PTY_RPC_OK"
p = rpc("run", "--pty", pty_script, pty=True)
assert b"PTY_RPC_OK" in p.stdout, p

p = rpc("bash", "--json", "--", "-lc", "printf BASH_RPC_OK", expected=None)
if p.returncode:
    assert b"Git Bash not found" in p.stderr or b"executable file not found" in p.stderr, p
    print("SKIP_GIT_BASH_NOT_INSTALLED")
else:
    assert json.loads(p.stdout)["stdout"] == "BASH_RPC_OK", p
    p = rpc("bash", "--", "-lc", "stty size; printf BASH_PTY_OK", pty=True)
    assert b"BASH_PTY_OK" in p.stdout, p

if is_windows:
    p = rpc("wsl", "--", "--list", "--quiet", expected=None)
    listing = p.stdout.replace(b"\x00", b"").strip()
    if p.returncode or not listing:
        print("SKIP_WSL_UNAVAILABLE", p.returncode)
    else:
        p = rpc("wsl", "--cwd", "/tmp", "--", "--exec", "sh", "-c", "pwd; printf WSL_RPC_OK")
        assert b"/tmp" in p.stdout and b"WSL_RPC_OK" in p.stdout, p

    # A timed-out command must kill descendants, not only its PowerShell parent.
    name = "assh-descendant-" + uuid.uuid4().hex + ".pid"
    path = result("run", "--json", "[IO.Path]::Combine([IO.Path]::GetTempPath(),'%s')" % name)["stdout"].strip()
    quoted = path.replace("'", "''")
    child = ("$p=Start-Process -FilePath (Get-Process -Id $PID).Path "
             "-ArgumentList '-NoLogo','-NoProfile','-Command','Start-Sleep 60' -PassThru; "
             "[IO.File]::WriteAllText('%s',[string]$p.Id); Start-Sleep 60" % quoted)
    result("run", "--json", "--timeout", "2s", child, expected=124)
    check = ("$childId=[int][IO.File]::ReadAllText('%s'); "
             "if (Get-Process -Id $childId -ErrorAction SilentlyContinue) { exit 9 }; "
             "Remove-Item -LiteralPath '%s'; Write-Output TREE_KILLED" % (quoted, quoted))
    assert "TREE_KILLED" in result("run", "--json", check)["stdout"]

print("TOOL_EXEC_OK")
