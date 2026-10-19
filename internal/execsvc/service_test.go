package execsvc

import (
	"agent_ssh/internal/toolproto"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()
	sh := "bash"
	if runtime.GOOS == "windows" {
		sh = "pwsh.exe"
		if _, e := exec.LookPath(sh); e != nil {
			sh = "powershell.exe"
		}
	}
	s := New(sh, t.TempDir(), t.TempDir())
	t.Cleanup(func() { s.Close() })
	return s
}
func call(t *testing.T, s *Service, args ...string) (map[string]any, error) {
	t.Helper()
	var o, e bytes.Buffer
	err := s.Handle(context.Background(), args, strings.NewReader(""), &o, &e)
	m := map[string]any{}
	if o.Len() > 0 {
		if je := json.Unmarshal(o.Bytes(), &m); je != nil {
			t.Fatalf("invalid JSON %q: %v stderr=%s", o.String(), je, e.String())
		}
	}
	return m, err
}
func TestRunJSONAndTimeout(t *testing.T) {
	s := testService(t)
	script := "printf '你好'; printf 'separate' >&2; exit 7"
	slow := "sleep 30"
	if runtime.GOOS == "windows" {
		script = "[Console]::Write('你好'); [Console]::Error.Write('separate'); exit 7"
		slow = "Start-Sleep 30"
	}
	m, e := call(t, s, "run", "--json", script)
	if toolproto.ExitCode(e) != 7 || m["stdout"] != "你好" || m["stderr"] != "separate" {
		t.Fatalf("%v %v", m, e)
	}
	started := time.Now()
	m, e = call(t, s, "run", "--json", "--timeout", "0.2", slow)
	if toolproto.ExitCode(e) != 124 || m["timed_out"] != true || time.Since(started) > 5*time.Second {
		t.Fatalf("%v %v", m, e)
	}
}
func TestDryRunNeverExecutes(t *testing.T) {
	s := testService(t)
	p := filepath.Join(s.workdir, "created")
	script := fmt.Sprintf("touch '%s'", p)
	if runtime.GOOS == "windows" {
		script = fmt.Sprintf("New-Item '%s'", p)
	}
	m, e := call(t, s, "run", "--dry-run", script)
	if e != nil || m["dry_run"] != true {
		t.Fatal(m, e)
	}
	if _, e = os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("dry-run created a file")
	}
	m, e = call(t, s, "run", script, "--dry-run")
	if e != nil || m["dry_run"] != true {
		t.Fatal("trailing dry-run failed", m, e)
	}
	for _, args := range [][]string{{"session", "new", "--dry-run"}, {"job", "start", script, "--dry-run"}, {"session", "send", "--dry-run", "nonexistent"}, {"session", "attach", "--dry-run", "nonexistent"}, {"job", "wait", "--dry-run", "nonexistent"}, {"job", "kill", "--dry-run", "nonexistent"}} {
		m, e = call(t, s, args...)
		if e != nil || m["dry_run"] != true {
			t.Fatal(args, m, e)
		}
	}
	if files, _ := os.ReadDir(s.workdir); len(files) > 0 {
		t.Fatal("dry-run created workdir files")
	}
	if files, _ := os.ReadDir(s.stateDir); len(files) > 0 {
		t.Fatal("dry-run created state files")
	}
	o, e := parse([]string{"--", "literal", "--dry-run"})
	if e != nil || o.dry || len(o.argv) != 2 {
		t.Fatal("-- did not preserve literal dry-run", o, e)
	}
}
func TestSessionPreservesStateAndJobSurvivesRequest(t *testing.T) {
	s := testService(t)
	m, e := call(t, s, "session", "new")
	if e != nil {
		t.Fatal(e)
	}
	id := m["id"].(string)
	script := "export ASSH_SESSION_TEST=preserved; mkdir child; cd child; printf '%s:%s\\n' \"$ASSH_SESSION_TEST\" \"$PWD\""
	check := "printf '%s:%s\\n' \"$ASSH_SESSION_TEST\" \"$PWD\""
	if runtime.GOOS == "windows" {
		script = "$env:ASSH_SESSION_TEST='preserved'; New-Item -ItemType Directory child | Out-Null; Set-Location child; Write-Output \"$env:ASSH_SESSION_TEST`:$PWD\""
		check = "Write-Output \"$env:ASSH_SESSION_TEST`:$PWD\""
	}
	if _, e = call(t, s, "session", "send", id, script); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		m, e = call(t, s, "session", "read", id, "--wait", "200ms")
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(fmt.Sprint(m["stdout"]), "preserved:") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(m)
		}
	}
	offset := fmt.Sprintf("%.0f", m["offset"].(float64))
	call(t, s, "session", "send", id, check)
	for {
		m, e = call(t, s, "session", "read", id, "--offset", offset, "--wait", "200ms")
		if strings.Contains(fmt.Sprint(m["stdout"]), "preserved:") && strings.Contains(fmt.Sprint(m["stdout"]), "child") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(m, e)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	job := "sleep 0.2; printf survived"
	if runtime.GOOS == "windows" {
		job = "Start-Sleep -Milliseconds 200; Write-Output survived"
	}
	e = s.Handle(ctx, []string{"job", "start", job}, nil, &out, &bytes.Buffer{})
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(out.Bytes(), &m)
	jid := m["id"].(string)
	m, e = call(t, s, "job", "wait", jid)
	if e != nil || !strings.Contains(fmt.Sprint(m["stdout"]), "survived") || m["exit_code"] != float64(0) {
		t.Fatal(m, e)
	}
}
func TestRingOffsets(t *testing.T) {
	b := &logBuffer{}
	b.Write(bytes.Repeat([]byte("x"), outputLimit+10))
	a, n, tr := b.snapshot(0)
	if len(a) != outputLimit || n != outputLimit+10 || !tr {
		t.Fatal(len(a), n, tr)
	}
	a, _, tr = b.snapshot(n)
	if a != "" || tr {
		t.Fatal(a, tr)
	}
}

func TestPTYResizeAndLifetime(t *testing.T) {
	s := testService(t)
	p, e := resolveShell(s.shell)
	if e != nil {
		t.Fatal(e)
	}
	var cmd *exec.Cmd
	if powerShell(p) {
		cmd = exec.Command(p, "-NoLogo", "-NoProfile", "-Command", "Write-Output PTY_READY; Start-Sleep -Seconds 1; Write-Output PTY_DONE")
	} else {
		cmd = exec.Command(p, "-c", "printf PTY_READY; sleep 0.2; printf PTY_DONE")
	}
	cmd.Dir = s.workdir
	term, e := startTerminal(cmd, Size{80, 24})
	if e != nil {
		t.Fatal(e)
	}
	defer term.Close()
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := term.Read(buf)
			out.Write(buf[:n])
			if e != nil {
				break
			}
		}
		close(done)
	}()
	if e = term.Resize(Size{100, 40}); e != nil {
		t.Fatal(e)
	}
	n, e := term.Wait()
	<-done
	if e != nil || n != 0 || !strings.Contains(out.String(), "PTY_DONE") {
		t.Fatal(n, e, out.String())
	}
}

func TestPersistentPTYSession(t *testing.T) {
	s := testService(t)
	m, e := call(t, s, "session", "new", "--pty")
	if e != nil {
		t.Fatal(e)
	}
	id := m["id"].(string)
	script := "export ASSH_PTY_VALUE='PTY_STATE_'\"VALUE\"; printf '%s\\n' \"$ASSH_PTY_VALUE\""
	if runtime.GOOS == "windows" {
		script = "$env:ASSH_PTY_VALUE='PTY_STATE_'+'VALUE'; Write-Output $env:ASSH_PTY_VALUE"
	}
	call(t, s, "session", "send", id, script)
	deadline := time.Now().Add(8 * time.Second)
	for {
		m, e = call(t, s, "session", "read", id, "--wait", "100ms")
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(fmt.Sprint(m["stdout"]), "PTY_STATE_VALUE") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(m)
		}
	}
	if _, e = call(t, s, "session", "close", id); e != nil {
		t.Fatal(e)
	}
}

func TestDryRunTaskMutations(t *testing.T) {
	s := testService(t)
	script := "sleep 30"
	if runtime.GOOS == "windows" {
		script = "Start-Sleep 30"
	}
	m, e := call(t, s, "job", "start", script)
	if e != nil {
		t.Fatal(e)
	}
	id := m["id"].(string)
	if _, e = call(t, s, "job", "kill", id, "--dry-run"); e != nil {
		t.Fatal(e)
	}
	m, e = call(t, s, "job", "log", id)
	if e != nil || m["running"] != true {
		t.Fatal("dry kill stopped task", m, e)
	}
	before := len(s.tasks)
	m, e = call(t, s, "job", "start", "--dry-run", script)
	if e != nil || len(s.tasks) != before {
		t.Fatal("dry start spawned task", m, e)
	}
	m, e = call(t, s, "session", "new")
	if e != nil {
		t.Fatal(e)
	}
	id = m["id"].(string)
	script = "touch dry-created"
	if runtime.GOOS == "windows" {
		script = "New-Item dry-created"
	}
	call(t, s, "session", "send", id, "--dry-run", script)
	call(t, s, "session", "close", id, "--dry-run")
	m, e = call(t, s, "session", "read", id)
	if e != nil || m["running"] != true {
		t.Fatal("dry close stopped session", m, e)
	}
	if _, e = os.Stat(filepath.Join(s.workdir, "dry-created")); !os.IsNotExist(e) {
		t.Fatal("dry send ran command")
	}
}

func TestSessionImportedModule(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell module behavior")
	}
	s := testService(t)
	m, e := call(t, s, "session", "new")
	if e != nil {
		t.Fatal(e)
	}
	id := m["id"].(string)
	_, e = call(t, s, "session", "send", id, "New-Module -Name ASSHPersist -ScriptBlock { function Get-ASSHPersist { 'MODULE_PRESERVED' }; Export-ModuleMember -Function Get-ASSHPersist } | Import-Module")
	if e != nil {
		t.Fatal(e)
	}
	call(t, s, "session", "send", id, "Get-ASSHPersist")
	deadline := time.Now().Add(8 * time.Second)
	for {
		m, e = call(t, s, "session", "read", id, "--wait", "100ms")
		if strings.Contains(fmt.Sprint(m["stdout"]), "MODULE_PRESERVED") {
			break
		}
		if e != nil || time.Now().After(deadline) {
			t.Fatal(m, e)
		}
	}
}

func TestPTYConcurrentResizeExit(t *testing.T) {
	s := testService(t)
	p, e := resolveShell(s.shell)
	if e != nil {
		t.Fatal(e)
	}
	var cmd *exec.Cmd
	if powerShell(p) {
		cmd = exec.Command(p, "-NoLogo", "-NoProfile", "-Command", "Start-Sleep -Milliseconds 200; Write-Output done")
	} else {
		cmd = exec.Command(p, "-c", "sleep 0.1; printf done")
	}
	term, e := startTerminal(cmd, Size{80, 24})
	if e != nil {
		t.Fatal(e)
	}
	defer term.Close()
	drained := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, e := term.Read(buf); e != nil {
				break
			}
		}
		close(drained)
	}()
	resizeDone := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(resizeDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = term.Resize(Size{100, 40})
			case <-stop:
				return
			}
		}
	}()
	n, e := term.Wait()
	close(stop)
	<-resizeDone
	<-drained
	if e != nil || n != 0 {
		t.Fatal(n, e)
	}
}

func TestRunPTYUsesScriptSemantics(t *testing.T) {
	s := testService(t)
	script := "printf 'RUN_PTY_SEMANTICS'"
	if runtime.GOOS == "windows" {
		script = "Write-Output ('RUN_PTY_'+'SEMANTICS')"
	}
	var out, errout bytes.Buffer
	e := s.Handle(context.Background(), []string{"run", "--pty", script}, strings.NewReader(""), &out, &errout)
	if e != nil || !strings.Contains(out.String(), "RUN_PTY_SEMANTICS") {
		t.Fatal(e, out.String(), errout.String())
	}
}

func TestCloseCancelsOrdinaryExecutionWithoutWaitingForStdin(t *testing.T) {
	s := testService(t)
	sentinel := filepath.Join(s.workdir, "running")
	script := fmt.Sprintf("touch '%s'; sleep 30", sentinel)
	if runtime.GOOS == "windows" {
		script = fmt.Sprintf("[IO.File]::WriteAllText('%s','yes'); Start-Sleep 30", sentinel)
	}
	inR, inW := io.Pipe()
	defer inW.Close()
	defer inR.Close()
	done := make(chan error, 1)
	go func() {
		var out, errout bytes.Buffer
		done <- s.Handle(context.Background(), []string{"run", script}, inR, &out, &errout)
	}()
	deadline := time.Now().Add(6 * time.Second)
	for {
		if _, e := os.Stat(sentinel); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("command did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(4 * time.Second):
		t.Fatal("Close deadlocked")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("execution did not return")
	}
}

func TestEqualsOptions(t *testing.T) {
	o, e := parse([]string{"--timeout=3s", "--shell=bash", "--cwd=/tmp", "--cols=100", "echo ok"})
	if e != nil || o.timeout != 3*time.Second || o.shell != "bash" || o.cwd != "/tmp" || o.cols != 100 || len(o.argv) != 1 {
		t.Fatal(o, e)
	}
}

func TestBashDirectArgvAndCWD(t *testing.T) {
	s := testService(t)
	if _, e := BashPath(); e != nil {
		t.Skip(e)
	}
	literal := "space $ quote ' 中文"
	m, e := call(t, s, "bash", "--json", "--", "-lc", "printf '%s\\n' \"$PWD\"; printf '%s' \"$1\"", "assh-argv", literal)
	if e != nil {
		t.Fatal(e, m)
	}
	out := m["stdout"].(string)
	if !strings.Contains(out, filepath.Base(s.workdir)) || !strings.HasSuffix(out, literal) {
		t.Fatal(out)
	}
}
