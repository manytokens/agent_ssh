package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"agent_ssh/internal/execsvc"
)

// An outer ConPTY represents Windows Terminal. The login itself creates the
// inner ConPTY for ssh; both initial geometry and resize must reach Linux.
func TestLoginTerminalGeometry(t *testing.T) {
	cli := os.Getenv("ASSH_TEST_LOGIN_EXE")
	if cli == "" {
		t.Skip("requires disposable relay")
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("ASSH_TEST_LOGIN_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	p, err := execsvc.StartTerminal(exec.Command(cli, args...), execsvc.Size{Cols: 117, Rows: 39})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	defer p.Kill()
	var mu sync.Mutex
	var output bytes.Buffer
	go func() {
		b := make([]byte, 4096)
		for {
			n, e := p.Read(b)
			mu.Lock()
			output.Write(b[:n])
			mu.Unlock()
			if e != nil {
				return
			}
		}
	}()
	wait := func(marker string) {
		t.Helper()
		deadline := time.Now().Add(35 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			text := output.String()
			mu.Unlock()
			if strings.Contains(text, marker) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("missing %q: %s", marker, output.String())
	}
	wait("Use assh help")
	// Ensure the final initialization command has completed before typing.
	time.Sleep(300 * time.Millisecond)
	io.WriteString(p, "printf '\\nGEOMETRY_START '; stty size\r")
	wait("GEOMETRY_START 39 117")
	if err := p.Resize(execsvc.Size{Cols: 143, Rows: 51}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	io.WriteString(p, "printf '\\nGEOMETRY_RESIZE '; stty size\r")
	wait("GEOMETRY_RESIZE 51 143")
	if os.Getenv("ASSH_TEST_SCREEN") == "1" {
		io.WriteString(p, "screen -S assh-geometry bash --noprofile --norc -i\r")
		time.Sleep(500 * time.Millisecond)
		io.WriteString(p, "printf '\\nSCREEN_GEOMETRY '; stty size\r")
		wait("SCREEN_GEOMETRY 51 143")
		if err := p.Resize(execsvc.Size{Cols: 151, Rows: 57}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
		io.WriteString(p, "printf '\\nSCREEN_RESIZE '; stty size\r")
		wait("SCREEN_RESIZE 57 151")
		io.WriteString(p, "exit\r")
		time.Sleep(300 * time.Millisecond)
	}
	io.WriteString(p, "exit\r")
	done := make(chan error, 1)
	go func() {
		code, e := p.Wait()
		if e == nil && code != 0 {
			e = fmt.Errorf("exit %d", code)
		}
		done <- e
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("login did not exit")
	}
}
