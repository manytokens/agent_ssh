package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"agent_ssh/internal/audit"
)

func TestGlobalTaskOptions(t *testing.T) {
	shell, script := "bash", "sleep 30"
	if runtime.GOOS == "windows" {
		shell, script = "pwsh.exe", "Start-Sleep -Seconds 30"
		if _, err := exec.LookPath(shell); err != nil {
			shell = "powershell.exe"
		}
	}
	s := New(Config{Shell: shell, WorkDir: t.TempDir(), StateDir: t.TempDir()})
	defer s.Close()
	call := func(args ...string) (map[string]any, error) {
		t.Helper()
		var out bytes.Buffer
		err := s.Handle(context.Background(), args, strings.NewReader(""), &out, io.Discard)
		var result map[string]any
		if err == nil {
			if e := json.Unmarshal(out.Bytes(), &result); e != nil {
				t.Fatal(e)
			}
		}
		return result, err
	}
	created, err := call("session", "new")
	if err != nil {
		t.Fatal(err)
	}
	id := created["id"].(string)
	for _, args := range [][]string{
		{"session", "read", id, "--json"},
		{"--json", "session", "read", id},
		{"--json", "session", "close", id},
	} {
		if _, err := call(args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	created, err = call("job", "start", script)
	if err != nil {
		t.Fatal(err)
	}
	id = created["id"].(string)
	if _, err := call("--json", "--timeout=20ms", "job", "wait", id); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait should honor global timeout: %v", err)
	}
	for _, action := range []string{"log", "kill", "wait"} {
		if _, err := call("--json", "job", action, id); err != nil {
			t.Fatalf("job %s: %v", action, err)
		}
	}
}

func TestAuditDirectAndMCPOperations(t *testing.T) {
	log, err := audit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	s := New(Config{WorkDir: t.TempDir(), Audit: log})
	defer s.Close()
	if err := s.Handle(context.Background(), []string{"ping"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	in, input := io.Pipe()
	output, out := io.Pipe()
	defer in.Close()
	defer input.Close()
	defer output.Close()
	defer out.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		err := s.Handle(audit.WithConnection(ctx, log, "connection-1", "agent"), []string{"mcp"}, in, out, io.Discard)
		out.Close()
		done <- err
	}()
	decoder := json.NewDecoder(output)
	for i, argv := range [][]string{{"ping"}, {"fs", "stat", "missing-file"}} {
		request := map[string]any{"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": map[string]any{"name": "command", "arguments": map[string]any{"argv": argv}}}
		if err := json.NewEncoder(input).Encode(request); err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response["error"] != nil {
			t.Fatalf("MCP protocol error: %v", response)
		}
	}
	// Entries must already exist while the MCP transport is still open.
	data, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatalf("want exactly one entry per operation: %s", data)
	}
	for i, line := range lines {
		var entry audit.Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Kind != "tool" || entry.ExitCode == nil {
			t.Fatalf("invalid entry: %+v", entry)
		}
		if i > 0 && (entry.Conn != "connection-1" || entry.User != "agent") {
			t.Fatalf("lost MCP attribution: %+v", entry)
		}
		if i == 2 && (*entry.ExitCode == 0 || entry.Error == "") {
			t.Fatalf("lost operation failure: %+v", entry)
		}
	}
	input.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MCP did not stop")
	}
}
