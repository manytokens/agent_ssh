"""A remote agent discovers its Windows connection using inherited env only."""
import json
import os
import shlex
import socket
import subprocess

e = os.environ
c = json.loads(e["ASSH_CONNECTION_JSON"])
assert c["port"] == int(e["ASSH_PORT"]) == 22224
assert c["host"] == e["ASSH_HOST"] == "127.0.0.1"
assert c["user"] == e["ASSH_USER"] == "agent"
assert c["host_key"] == e["ASSH_HOST_KEY"]
assert c["target_os"] == e["ASSH_TARGET_OS"] == "windows"
assert e["ASSH_AGENT_SOCKET"]
with socket.create_connection((c["host"], c["port"]), timeout=5):
    pass
command = shlex.split(e["ASSH_SSH_COMMAND"])
result = subprocess.run([*command, "[Console]::Write('ENV_DISCOVERY_OK')"], capture_output=True, timeout=15)
assert result.returncode == 0 and result.stdout == b"ENV_DISCOVERY_OK", (result.stdout, result.stderr)
scp = shlex.split(e["ASSH_SCP_COMMAND"])
result = subprocess.run([*scp, f'{c["user"]}@{c["host"]}:relay.pub', "/tmp/assh-env-copy"], capture_output=True, timeout=15)
assert result.returncode == 0, result.stderr
os.unlink("/tmp/assh-env-copy")
print("ASSH_ENV_OK", flush=True)
