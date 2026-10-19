package execsvc

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestJobDiskPagingAndHistory(t *testing.T) {
	s := testService(t)
	script := "printf disk-history"
	if runtime.GOOS == "windows" {
		script = "Write-Output disk-history"
	}
	m, e := call(t, s, "job", "start", script)
	if e != nil {
		t.Fatal(e)
	}
	id := m["id"].(string)
	if _, e = call(t, s, "job", "wait", id); e != nil {
		t.Fatal(e)
	}
	s.Close()
	data := bytes.Repeat([]byte("x"), outputLimit+123)
	if e = os.WriteFile(filepath.Join(s.jobDir(id), "stdout.log"), data, 0600); e != nil {
		t.Fatal(e)
	}
	s2 := New(s.shell, s.workdir, s.stateDir)
	defer s2.Close()
	m, e = call(t, s2, "job", "log", id)
	if e != nil || len(m["stdout"].(string)) != outputLimit || m["has_more"] != true || m["truncated"] != false || m["running"] != false {
		t.Fatal("bad log page", e)
	}
	m, e = call(t, s2, "job", "log", id, "--offset", "4194304")
	if e != nil || len(m["stdout"].(string)) != 123 || m["has_more"] != false {
		t.Fatal("bad second log page", e)
	}
}
func TestInterruptedHistory(t *testing.T) {
	s := testService(t)
	task := &task{id: strings.Repeat("a", 24), kind: "job", started: time.Now()}
	if e := s.prepareDisk(task); e != nil {
		t.Fatal(e)
	}
	task.diskOut.Write([]byte("before interrupt"))
	task.closeDisk()
	s2 := New(s.shell, s.workdir, s.stateDir)
	defer s2.Close()
	m, e := call(t, s2, "job", "wait", task.id)
	if e != nil || m["interrupted"] != true || m["exit_code"] != float64(130) || m["stdout"] != "before interrupt" {
		t.Fatal(m, e)
	}
}

func TestEmptyStateDoesNotCreateJobStore(t *testing.T) {
	s := New("bash", t.TempDir(), "")
	defer s.Close()
	if len(s.tasks) != 0 {
		t.Fatal("loaded history without state directory")
	}
	if e := s.prepareDisk(&task{id: strings.Repeat("c", 24), kind: "job"}); e == nil {
		t.Fatal("accepted disk job without state directory")
	}
}
