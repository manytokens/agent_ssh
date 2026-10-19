//go:build windows

package execsvc

import (
	"agent_ssh/internal/toolproto"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWSLCWDIsNotWindowsProcessDirectory(t *testing.T) {
	if _, e := exec.LookPath("wsl.exe"); e != nil {
		t.Skip(e)
	}
	s := testService(t)
	cmd, _, e := s.command("wsl", options{cwd: "/tmp", argv: []string{"--exec", "sh", "-c", "pwd"}})
	if e != nil || cmd.Dir != s.workdir || !strings.Contains(strings.Join(cmd.Args, " "), "--cd /tmp --exec") {
		t.Fatal(cmd, e)
	}
}

func TestTimeoutKillsWindowsDescendant(t *testing.T) {
	s := testService(t)
	pidPath := filepath.Join(s.workdir, "child.pid")
	script := fmt.Sprintf("$p=Start-Process -FilePath '%s' -ArgumentList '-NoLogo','-NoProfile','-Command','Start-Sleep 60' -PassThru; [IO.File]::WriteAllText('%s',[string]$p.Id); Start-Sleep 60", strings.ReplaceAll(s.shell, "'", "''"), strings.ReplaceAll(pidPath, "'", "''"))
	m, e := call(t, s, "run", "--json", "--timeout", "2s", script)
	if toolproto.ExitCode(e) != 124 {
		t.Fatal(m, e)
	}
	b, e := os.ReadFile(pidPath)
	if e != nil {
		t.Fatal("child not started before timeout", e)
	}
	pid, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for {
		h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if e != nil {
			return
		}
		var code uint32
		e = windows.GetExitCodeProcess(h, &code)
		windows.CloseHandle(h)
		if e != nil || code != 259 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout left child %d alive", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func alive(pid uint32) bool {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if e != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259
}

// A grandchild started through cmd.exe must die with the command; Store
// pwsh.exe creates such processes outside the command's job object.
func TestTimeoutKillsGrandchildThroughCmd(t *testing.T) {
	s := testService(t)
	pidPath := filepath.Join(s.workdir, "grandchild.pid")
	inner := encodePowerShell(fmt.Sprintf("[IO.File]::WriteAllText('%s',[string]$PID); Start-Sleep 60", strings.ReplaceAll(pidPath, "'", "''")))
	script := `cmd /c "powershell.exe -NoLogo -NoProfile -EncodedCommand ` + inner + `"`
	started := time.Now()
	// The grandchild is a second Windows PowerShell, whose cold start on a CI
	// runner can take several seconds; it must be up before the timeout fires.
	m, e := call(t, s, "run", "--json", "--timeout", "20s", script)
	if toolproto.ExitCode(e) != 124 || m["timed_out"] != true {
		t.Fatal(m, e)
	}
	if d := time.Since(started); d > 25*time.Second {
		t.Fatalf("timeout took %v", d)
	}
	b, e := os.ReadFile(pidPath)
	if e != nil {
		t.Fatal("grandchild not started before timeout", e)
	}
	pid, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	deadline := time.Now().Add(2 * time.Second)
	for alive(uint32(pid)) {
		if time.Now().After(deadline) {
			t.Fatalf("timeout left grandchild %d alive", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPowerShellExitCodesAndOutput(t *testing.T) {
	s := testService(t)
	for _, c := range []struct {
		script string
		code   int
		stdout string
	}{
		{`cmd /c "exit 7"`, 7, ""},
		{`"before"; cmd /c "exit 3"`, 3, "before"},
		{`cmd /c "exit 7"; "after"`, 0, "after"},
		{`exit 5`, 5, ""},
		{`Write-Error boom`, 1, ""},
		{`Get-Location; "MARK"`, 0, "MARK"},
		{`if (`, 1, ""},
	} {
		m, e := call(t, s, "run", "--json", c.script)
		if toolproto.ExitCode(e) != c.code || int(m["exit_code"].(float64)) != c.code || !strings.Contains(m["stdout"].(string), c.stdout) {
			t.Errorf("%q: exit %v %v stdout %q stderr %q", c.script, toolproto.ExitCode(e), m["exit_code"], m["stdout"], m["stderr"])
		}
		if strings.Contains(m["stderr"].(string), "CLIXML") || strings.Contains(m["stdout"].(string)+m["stderr"].(string), "\x1b[") {
			t.Errorf("%q: serialized or colored output %q %q", c.script, m["stdout"], m["stderr"])
		}
	}
	m, _ := call(t, s, "run", "--json", "Get-Location")
	// PowerShell expands Windows 8.3 aliases in the runner's TEMP directory.
	// Check the formatted table and unique leaf, independent of ancestor aliases.
	if !strings.Contains(m["stdout"].(string), "Path") || !strings.Contains(m["stdout"].(string), filepath.Base(s.workdir)) {
		t.Errorf("formatted output lost: %q", m["stdout"])
	}
}

func TestLongPowerShellScript(t *testing.T) {
	s := testService(t)
	script := "$x = '" + strings.Repeat("a", 60000) + "'; $x.Length"
	m, e := call(t, s, "run", "--json", script)
	if e != nil || strings.TrimSpace(m["stdout"].(string)) != "60000" {
		t.Fatal(m, e)
	}
	if left, _ := filepath.Glob(filepath.Join(os.TempDir(), "assh-*.ps1")); len(left) > 0 {
		for _, f := range left {
			if st, err := os.Stat(f); err == nil && time.Since(st.ModTime()) < time.Minute {
				t.Fatalf("script file left behind: %s", f)
			}
		}
	}
}

func TestSessionMultilineSend(t *testing.T) {
	s := testService(t)
	m, e := call(t, s, "session", "new")
	if e != nil {
		t.Fatal(e)
	}
	id := m["id"].(string)
	defer call(t, s, "session", "close", id)
	if _, e = call(t, s, "session", "send", id, "foreach ($i in 1..3) {\n  \"line$i\"\n}"); e != nil {
		t.Fatal(e)
	}
	call(t, s, "session", "send", id, `"after"`)
	deadline := time.Now().Add(20 * time.Second)
	for {
		m, _ = call(t, s, "session", "read", id, "--offset", "0", "--wait", "2s")
		out := m["stdout"].(string)
		if strings.Contains(out, "line3") && strings.Contains(out, "after") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("multi-line send stalled the session: %q", out)
		}
	}
}

// After a crash the job object is gone but escaped descendants live on; the
// next service start ends those recorded in processes.json.
func TestRestartEndsRecordedProcesses(t *testing.T) {
	s := testService(t)
	pidPath := filepath.Join(s.workdir, "orphan.pid")
	inner := encodePowerShell(fmt.Sprintf("[IO.File]::WriteAllText('%s',[string]$PID); Start-Sleep 60", strings.ReplaceAll(pidPath, "'", "''")))
	if _, e := call(t, s, "job", "start", `cmd /c "powershell.exe -NoLogo -NoProfile -EncodedCommand `+inner+`"`); e != nil {
		t.Fatal(e)
	}
	var pid uint64
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, e := os.ReadFile(pidPath)
		if e == nil {
			if pid, e = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); e == nil && pid > 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("grandchild did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var recorded []byte
	for {
		recorded, _ = os.ReadFile(s.processFile())
		if strings.Contains(string(recorded), fmt.Sprintf(`"pid":%d,`, pid)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d not recorded: %s", pid, recorded)
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Start a second service from the recorded state, as after a crash.
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "processes.json"), recorded, 0600); e != nil {
		t.Fatal(e)
	}
	restarted := New(s.shell, t.TempDir(), dir)
	defer restarted.Close()
	// Reaping is synchronous in New; check before its tracker first writes.
	if _, e := os.Stat(filepath.Join(dir, "processes.json")); !os.IsNotExist(e) {
		t.Fatal("record not consumed")
	}
	for end := time.Now().Add(3 * time.Second); alive(uint32(pid)); {
		if time.Now().After(end) {
			t.Fatalf("recorded grandchild %d still alive after restart", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
