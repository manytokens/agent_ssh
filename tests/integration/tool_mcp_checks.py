"""Exercise the real reverse-SSH MCP transport from the initialized relay shell.

Run with python3 /workspace/tests/integration/tool_mcp_checks.py. Only temporary
files below the connected computer's work/integration directory are modified.
"""
import base64
import hashlib
import json
import os
import selectors
import shlex
import subprocess
import threading
import time


class MCP:
    def __init__(self):
        argv = base64.b64encode(b"mcp\0").decode("ascii")
        self.process = subprocess.Popen(
            [*shlex.split(os.environ["ASSH_SSH_COMMAND"]), "__assh_rpc_v1 " + argv],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.sequence = 0
        self.pending = {}
        self.buffer = b""
        self.errors = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.error_reader = threading.Thread(target=self._drain_errors, daemon=True)
        self.error_reader.start()

    def _drain_errors(self):
        while True:
            data = self.process.stderr.read(4096)
            if not data:
                return
            if len(self.errors) < 65536:
                self.errors.extend(data)

    def send(self, method, params=None, notification=False):
        message = {"jsonrpc": "2.0", "method": method}
        if not notification:
            self.sequence += 1
            message["id"] = self.sequence
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
        self.process.stdin.flush()
        return message.get("id")

    def receive(self, request_id, timeout=40):
        deadline = time.monotonic() + timeout
        while request_id not in self.pending:
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                # Any welcome banner/CLI noise on stdout fails here.
                response = json.loads(line)
                assert response["jsonrpc"] == "2.0", response
                self.pending[response["id"]] = response
            if request_id in self.pending:
                break
            remaining = deadline - time.monotonic()
            assert remaining > 0, ("MCP response timed out", request_id, self.errors)
            assert self.selector.select(remaining), ("MCP stdout stalled", request_id, self.errors)
            data = os.read(self.process.stdout.fileno(), 65536)
            assert data, ("MCP stdout closed", self.process.poll(), self.errors)
            self.buffer += data
        response = self.pending.pop(request_id)
        assert "error" not in response, response
        return response["result"]

    def call(self, name, arguments=None):
        result = self.receive(self.send("tools/call", {"name": name, "arguments": arguments or {}}))
        structured = result["structuredContent"]
        assert json.loads(result["content"][0]["text"]) == structured
        assert structured["exit_code"] == 0 and not result["isError"], structured
        assert not structured["truncated"], structured
        return structured

    def close(self):
        self.process.stdin.close()
        try:
            code = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise AssertionError("MCP did not exit after stdin EOF")
        finally:
            self.selector.close()
            self.error_reader.join(timeout=3)
            self.process.stdout.close()
            self.process.stderr.close()
        assert code == 0, (code, self.errors)


mcp = MCP()
scratch = None
windows = os.environ.get("ASSH_TARGET_OS") == "windows"


def literal(path):
    return "'" + path.replace("'", "''") + "'" if windows else shlex.quote(path)


try:
    initialized = mcp.receive(mcp.send("initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "assh-integration", "version": "1"},
    }))
    assert initialized["protocolVersion"] == "2025-06-18"
    assert "tools" in initialized["capabilities"]
    mcp.send("notifications/initialized", notification=True)
    tools = mcp.receive(mcp.send("tools/list"))["tools"]
    names = {tool["name"] for tool in tools}
    assert {"run", "put", "get", "ls", "hash", "info", "session", "job"} <= names, names
    assert all(tool["inputSchema"]["type"] == "object" for tool in tools)
    help_result = mcp.call("command", {"argv": ["help"]})
    assert "assh" in help_result["stdout"].lower()
    assert "ASSH_READY_" not in help_result["stdout"]
    info = json.loads(mcp.call("info")["stdout"])
    assert info["identity"]["username"] and info["cwd"]
    expected = "MCP_STDOUT_中文"
    script = "[Console]::Write('" + expected + "')" if windows else "printf '%s' " + shlex.quote(expected)
    assert mcp.call("run", {"command": script})["stdout"] == expected
    failure = mcp.receive(mcp.send("tools/call", {"name": "run", "arguments": {"command": "exit 7"}}))
    assert failure["isError"] and failure["structuredContent"]["exit_code"] == 7, failure
    scratch = info["cwd"].replace("\\", "/").rstrip("/") + "/work/integration/mcp-check-" + str(os.getpid())
    mcp.call("fs", {"argv": ["mkdir", scratch]})
    path = scratch + "/数据.bin"
    binary = bytes(range(256)) * 4097
    uploaded = mcp.call("put", {"path": path, "stdin_base64": base64.b64encode(binary).decode("ascii")})
    assert json.loads(uploaded["stdout"])["sha256"] == hashlib.sha256(binary).hexdigest()
    downloaded = mcp.call("get", {"path": path})
    assert base64.b64decode(downloaded["stdout_base64"]) == binary
    assert downloaded["binary"]
    digest = json.loads(mcp.call("hash", {"path": path})["stdout"])
    assert digest["sha256"] == hashlib.sha256(binary).hexdigest(), digest
    rows = json.loads(mcp.call("ls", {"path": scratch})["stdout"])
    assert any(row["name"] == "数据.bin" for row in rows), rows
    absent = scratch + "/dry-run-must-not-exist"
    dry_script = ("[IO.File]::WriteAllText(" + literal(absent) + ",'unexpected')") if windows else ("printf unexpected > " + literal(absent))
    dry = json.loads(mcp.call("run", {"command": dry_script, "dry_run": True})["stdout"])
    assert dry["dry_run"] is True, dry
    dry = json.loads(mcp.call("command", {"argv": ["dry-run", "put", absent], "stdin_base64": "dW5leHBlY3RlZA=="})["stdout"])
    assert dry["dry_run"] is True, dry
    rows = json.loads(mcp.call("ls", {"path": scratch})["stdout"])
    assert all(row["name"] != "dry-run-must-not-exist" for row in rows), rows
    watch_id = mcp.send("tools/call", {"name": "command", "arguments": {"argv": ["watch", scratch]}})
    assert mcp.receive(mcp.send("ping")) == {}
    mcp.send("notifications/cancelled", {"requestId": watch_id, "reason": "integration complete"}, notification=True)
    # MCP: the cancelled request is never answered; later requests still are.
    time.sleep(2)
    assert mcp.receive(mcp.send("ping")) == {}
    assert watch_id not in mcp.pending, mcp.pending[watch_id]
finally:
    try:
        if scratch:
            cleanup = "Remove-Item -LiteralPath " + literal(scratch) + " -Recurse -Force" if windows else "rm -rf -- " + literal(scratch)
            mcp.call("run", {"command": cleanup})
    finally:
        mcp.close()

print("ASSH_MCP_OK", flush=True)
