package localssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"agent_ssh/internal/audit"
	"agent_ssh/internal/state"
	"agent_ssh/internal/telemetry"
	"agent_ssh/internal/toolrpc"
	"agent_ssh/internal/tools"
	"golang.org/x/crypto/ssh"
)

func TestAgentToolsOverAuthenticatedSSH(t *testing.T) {
	dir, work := t.TempDir(), t.TempDir()
	if err := state.Init(dir); err != nil {
		t.Fatal(err)
	}
	shell, err := ResolveShell("")
	if err != nil {
		t.Fatal(err)
	}
	svc := tools.New(tools.Config{Shell: shell, WorkDir: work, StateDir: dir})
	defer svc.Close()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	metrics := &telemetry.Metrics{}
	auditLog, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	l, done, err := StartWithTools(ctx, dir, shell, work, slog.New(slog.NewTextHandler(io.Discard, nil)), svc.Handle, metrics, auditLog, signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("SSH tools did not stop")
		}
	})
	host, _ := state.HostSigner(dir)
	client, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rpc := func(args ...string) ([]byte, []byte, error) {
		t.Helper()
		session, e := client.NewSession()
		if e != nil {
			t.Fatal(e)
		}
		defer session.Close()
		var stderr bytes.Buffer
		session.Stderr = &stderr
		stdout, e := session.Output(toolrpc.Encode(args))
		return stdout, stderr.Bytes(), e
	}
	script := "printf OK; printf ERR >&2; exit 7"
	if runtime.GOOS == "windows" {
		script = "[Console]::Write('OK'); [Console]::Error.Write('ERR'); exit 7"
	}
	b, stderr, err := rpc("run", "--json", script)
	var exitErr *ssh.ExitError
	if err == nil {
		t.Fatal("exit code lost")
	}
	exitErr, _ = err.(*ssh.ExitError)
	if exitErr == nil || exitErr.ExitStatus() != 7 {
		t.Fatal(err)
	}
	var result map[string]any
	if e := json.Unmarshal(b, &result); e != nil || result["stdout"] != "OK" || result["stderr"] != "ERR" || len(stderr) != 0 {
		t.Fatalf("%s %q %v", b, stderr, e)
	}
	b, _, err = rpc("dry-run", "fs", "mkdir", "missing")
	if err != nil || !bytes.Contains(b, []byte(`"dry_run":true`)) {
		t.Fatalf("%s %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(work, "missing")); !os.IsNotExist(err) {
		t.Fatal("dry-run created a directory")
	}
	if b, _, err = rpc("capabilities", "--json"); err != nil || !bytes.Contains(b, []byte(`"root_restriction":false`)) {
		t.Fatalf("%s %v", b, err)
	}
	if metrics.Read.Load() == 0 || metrics.Written.Load() == 0 {
		t.Fatal("SSH metrics were not counted")
	}
	t.Run("MCP EOF reports successful exit", func(t *testing.T) {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		stdin, err := session.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Start(toolrpc.Encode([]string{"mcp"})); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(stdin, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"); err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := json.NewDecoder(stdout).Decode(&response); err != nil {
			t.Fatal(err)
		}
		if response["id"] != float64(1) || response["result"] == nil {
			t.Fatal(response)
		}
		stdin.Close()
		done := make(chan error, 1)
		go func() { done <- session.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("normal MCP EOF lost SSH exit-status: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("MCP EOF did not exit")
		}
	})
	plain, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, e := plain.Output("echo audited"); e != nil || !bytes.Contains(out, []byte("audited")) {
		t.Fatalf("plain exec: %q %v", out, e)
	}
	plain.Close()
	// Every connection, tool call and plain exec is in the audit log.
	logged, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	kinds := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(logged)), "\n") {
		var e audit.Entry
		if json.Unmarshal([]byte(line), &e) != nil {
			t.Fatalf("bad audit line %q", line)
		}
		kinds[e.Kind] = true
		if e.Kind == "tool" && len(e.Args) > 0 && e.Args[0] == "run" && (e.ExitCode == nil || *e.ExitCode != 7 || e.User != "agent" || e.Conn == "") {
			t.Fatalf("run entry: %+v", e)
		}
		if e.Kind == "exec" && (len(e.Args) != 1 || e.Args[0] != "echo audited" || *e.ExitCode != 0) {
			t.Fatalf("exec entry: %+v", e)
		}
	}
	if !kinds["connect"] || !kinds["tool"] || !kinds["exec"] {
		t.Fatalf("audit kinds %v in %s", kinds, logged)
	}
	// A native shell gets its own hint once and real PTY input, unlike exec/MCP.
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err = session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = io.Discard
	session.Stdin = strings.NewReader("echo ASSH_SHELL_OK\r\nexit\r\n")
	if err = session.Start(toolrpc.Encode([]string{"shell"})); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	select {
	case err = <-wait:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		session.Close()
		t.Fatal("PTY shell did not exit")
	}
	if !strings.Contains(output.String(), "ASSH_SHELL_OK") || strings.Count(output.String(), "assh: ") != 1 {
		t.Fatalf("shell output %q", output.String())
	}
}
