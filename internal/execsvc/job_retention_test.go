package execsvc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentJobLogAndCleanup(t *testing.T) {
	s := &Service{stateDir: t.TempDir(), tasks: make(map[string]*task)}
	j := &task{id: "concurrent", kind: "job", done: make(chan struct{}), started: time.Now(), finished: time.Now()}
	if err := s.prepareDisk(j); err != nil {
		t.Fatal(err)
	}
	if _, err := j.diskOut.Write(bytes.Repeat([]byte("x"), outputLimit)); err != nil {
		t.Fatal(err)
	}
	j.closeDisk()
	close(j.done)
	s.tasks[j.id] = j
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 10; n++ {
				j.diskResult(0, 0)
			}
		}()
	}
	var out bytes.Buffer
	if err := s.manageJobs([]string{"remove", j.id}, &out); err != nil {
		t.Fatal("cleanup collided with reader", err)
	}
	wg.Wait()
	if _, err := os.Stat(j.logDir); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestJobCappedPartialUTF8PreservesBytes(t *testing.T) {
	s := &Service{stateDir: t.TempDir()}
	j := &task{id: "utf8", kind: "job", done: make(chan struct{}), started: time.Now()}
	if err := s.prepareDisk(j); err != nil {
		t.Fatal(err)
	}
	j.diskOut.limit = 1
	if n, err := j.diskOut.Write([]byte("中")); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	// While running, the incomplete character remains available at offset 0.
	m := j.diskResult(0, 0)
	if m["offset"] != int64(0) || m["stdout"] != "" || m["log_truncated"] != true {
		t.Fatal(m)
	}
	j.closeDisk()
	close(j.done)
	m = j.diskResult(0, 0)
	want := base64.StdEncoding.EncodeToString([]byte("中")[:1])
	if m["stdout_base64"] != want || m["offset"] != int64(1) {
		t.Fatal(m)
	}
}

func TestJobLogBudgetDrainsAndPersists(t *testing.T) {
	dir := t.TempDir()
	l, err := openJobLog(filepath.Join(dir, "stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	l.limit = 5
	for _, p := range []string{"abc", "defgh", "more"} {
		n, err := l.Write([]byte(p))
		if n != len(p) || err != nil {
			t.Fatalf("did not drain: %d %v", n, err)
		}
	}
	if !l.Truncated() {
		t.Fatal("missing truncation flag")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "stdout.log"))
	if err != nil || string(b) != "abcde" {
		t.Fatalf("unbounded/incorrect log: %q %v", b, err)
	}
	s := &Service{}
	task := &task{id: "test", logDir: dir, diskOut: l, started: time.Now(), logTruncated: false}
	if err := s.persist(task, false); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec jobRecord
	if err := json.Unmarshal(b, &rec); err != nil || !rec.LogTruncated {
		t.Fatalf("truncation not persisted: %+v %v", rec, err)
	}
}

func addRetentionJob(t *testing.T, s *Service, id string, age time.Duration, running bool) *task {
	t.Helper()
	dir := s.jobDir(id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j := &task{id: id, kind: "job", logDir: dir, finished: time.Now().Add(-age), done: make(chan struct{})}
	if !running {
		close(j.done)
	}
	s.tasks[id] = j
	return j
}

func TestJobCleanupPreviewFiltersAndRunningProtection(t *testing.T) {
	s := &Service{stateDir: t.TempDir(), tasks: make(map[string]*task)}
	old := addRetentionJob(t, s, "old", 48*time.Hour, false)
	addRetentionJob(t, s, "new", time.Hour, false)
	addRetentionJob(t, s, "running", 96*time.Hour, true)
	var out bytes.Buffer
	if err := s.manageJobs([]string{"clean", "--older-than", "24h", "--dry-run"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"old"`) || strings.Contains(out.String(), `"new"`) || len(s.tasks) != 3 {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(old.logDir); err != nil {
		t.Fatal("dry run deleted files", err)
	}
	if err := s.manageJobs([]string{"remove", "running"}, &out); err == nil {
		t.Fatal("deleted running job")
	}
	if err := s.manageJobs([]string{"clean", "--older-than", "24h"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(s.tasks) != 2 || s.tasks["old"] != nil {
		t.Fatal("age filter failed")
	}
	if _, err := os.Stat(old.logDir); !os.IsNotExist(err) {
		t.Fatal("did not remove disk logs", err)
	}
	if err := s.manageJobs([]string{"remove", "new"}, &out); err != nil {
		t.Fatal(err)
	}
	if len(s.tasks) != 1 || s.tasks["running"] == nil {
		t.Fatal("running task affected")
	}
}

func TestAutomaticJobRetentionBoundsAgeAndCount(t *testing.T) {
	s := &Service{stateDir: t.TempDir(), tasks: make(map[string]*task)}
	addRetentionJob(t, s, "expired", 8*24*time.Hour, false)
	addRetentionJob(t, s, "running", 9*24*time.Hour, true)
	for i := 0; i < 105; i++ {
		addRetentionJob(t, s, fmt.Sprintf("recent-%03d", i), time.Duration(i)*time.Minute, false)
	}
	s.pruneJobs()
	if len(s.tasks) != 101 || s.tasks["expired"] != nil || s.tasks["running"] == nil || s.tasks["recent-104"] != nil || s.tasks["recent-000"] == nil {
		t.Fatalf("retention failed: %d", len(s.tasks))
	}
}
