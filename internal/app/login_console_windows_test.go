package app

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"agent_ssh/internal/platform"
	"golang.org/x/sys/windows"
)

// The integration runner invokes this with an isolated relay configuration.
// A hidden real console exercises native OpenSSH's console input path, which
// redirected-stdin integration tests cannot exercise.
func TestNativeConsoleLogin(t *testing.T) {
	cli := os.Getenv("ASSH_TEST_LOGIN_EXE")
	if cli == "" {
		t.Skip("integration console harness")
	}
	if os.Getenv("ASSH_TEST_CONSOLE_CHILD") != "1" {
		exe, _ := os.Executable()
		cmd := exec.Command(exe, "-test.run=^TestNativeConsoleLogin$", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "ASSH_TEST_CONSOLE_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE, HideWindow: true}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	os.Stdin = input
	if err := windows.SetStdHandle(windows.STD_INPUT_HANDLE, windows.Handle(input.Fd())); err != nil {
		t.Fatal(err)
	}
	write, ok := platform.ConsoleInput()
	if !ok {
		t.Fatal("test did not create a real console")
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("ASSH_TEST_LOGIN_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(cli, args...)
	cmd.Stdin, cmd.Stderr = input, os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	ready := make(chan struct{})
	readDone := make(chan struct{})
	var output bytes.Buffer
	go func() {
		defer close(readDone)
		var once sync.Once
		b := make([]byte, 4096)
		for {
			n, err := stdout.Read(b)
			output.Write(b[:n])
			// ConPTY may render the final space as CSI 1 C.
			if bytes.Contains(output.Bytes(), []byte("ASSH_TEST_PROMPT>")) {
				once.Do(func() { close(ready) })
			}
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(25 * time.Second):
		cmd.Process.Kill()
		<-readDone
		t.Fatalf("console login did not initialize: %s", output.String())
	}
	if err := write("python3 /workspace/tests/integration/env_checks.py; exit\n"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	<-readDone
	if !bytes.Contains(output.Bytes(), []byte("ASSH_ENV_OK")) || !bytes.Contains(output.Bytes(), []byte("ASSH_TEST_REAL_MOTD")) {
		t.Fatalf("console login: %s", output.String())
	}
	_, _ = io.WriteString(os.Stdout, "PASS native console, real MOTD and environment\n")
}
