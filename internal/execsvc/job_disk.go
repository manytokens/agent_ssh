package execsvc

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type jobRecord struct {
	ID           string    `json:"id"`
	Started      time.Time `json:"started"`
	Finished     time.Time `json:"finished"`
	ExitCode     int       `json:"exit_code"`
	Running      bool      `json:"running"`
	TimedOut     bool      `json:"timed_out"`
	Interrupted  bool      `json:"interrupted"`
	LogTruncated bool      `json:"log_truncated"`
}

const jobLogLimit = 32 << 20

// jobLog continues accepting output after the disk budget is exhausted, so a
// verbose process cannot fill the disk or block on its stdout/stderr pipe.
type jobLog struct {
	mu          sync.Mutex
	file        *os.File
	size, limit int64
	truncated   bool
}

func openJobLog(path string) (*jobLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &jobLog{file: f, size: st.Size(), limit: jobLogLimit}, nil
}
func (l *jobLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	left := l.limit - l.size
	if int64(len(p)) > left {
		l.truncated = true
		if left < 0 {
			left = 0
		}
		p = p[:int(left)]
	}
	if len(p) > 0 {
		written, err := l.file.Write(p)
		l.size += int64(written)
		if err != nil {
			return written, err
		}
	}
	return n, nil
}
func (l *jobLog) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
func (l *jobLog) Truncated() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.truncated
}

func (s *Service) jobDir(id string) string { return filepath.Join(s.stateDir, "jobs", id) }
func (s *Service) prepareDisk(t *task) error {
	if t.kind != "job" {
		return nil
	}
	if s.stateDir == "" {
		return fmt.Errorf("background jobs require a persistent state directory")
	}
	t.stdout.discard = true
	t.stderr.discard = true
	dir := s.jobDir(t.id)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	var e error
	t.diskOut, e = openJobLog(filepath.Join(dir, "stdout.log"))
	if e != nil {
		return e
	}
	t.diskErr, e = openJobLog(filepath.Join(dir, "stderr.log"))
	if e != nil {
		t.diskOut.Close()
		return e
	}
	t.logDir = dir
	return s.persist(t, true)
}
func (s *Service) persist(t *task, running bool) error {
	if t.logDir == "" {
		return nil
	}
	t.mu.Lock()
	rec := jobRecord{ID: t.id, Started: t.started, Finished: t.finished, ExitCode: t.exitCode, Running: running, TimedOut: t.timedOut, Interrupted: t.interrupted, LogTruncated: t.logTruncated}
	t.mu.Unlock()
	rec.LogTruncated = rec.LogTruncated || t.diskOut.Truncated() || t.diskErr.Truncated()
	b, e := json.Marshal(rec)
	if e != nil {
		return e
	}
	p := filepath.Join(t.logDir, "result.json")
	tmp := p + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, p)
}
func (t *task) closeDisk() {
	if t.diskOut != nil {
		t.diskOut.Close()
	}
	if t.diskErr != nil {
		t.diskErr.Close()
	}
}

// Return bounded pages of the retained prefix. Offsets are byte offsets.
func diskPage(path string, offset int64, final bool) (text string, next, total int64, err error) {
	f, e := os.Open(path)
	if e != nil {
		return "", offset, 0, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return "", offset, 0, e
	}
	total = st.Size()
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	b, e := io.ReadAll(io.NewSectionReader(f, offset, outputLimit))
	if offset+int64(len(b)) < total || !final {
		b = []byte(trimIncompleteUTF8(string(b)))
	}
	return string(b), offset + int64(len(b)), total, e
}
func (t *task) diskResult(offset, stderrOffset int64) map[string]any {
	t.logMu.Lock()
	defer t.logMu.Unlock()
	m := t.resultMemory(offset)
	final := m["running"] == false
	a, next, total, e := diskPage(filepath.Join(t.logDir, "stdout.log"), offset, final)
	b, en, et, ee := diskPage(filepath.Join(t.logDir, "stderr.log"), stderrOffset, final)
	setStreamResult(m, "stdout", a)
	setStreamResult(m, "stderr", b)
	m["offset"] = next
	m["stderr_offset"] = en
	m["stdout_size"] = total
	m["stderr_size"] = et
	m["has_more"] = next < total || en < et
	t.mu.Lock()
	truncated := t.logTruncated
	t.mu.Unlock()
	truncated = truncated || t.diskOut.Truncated() || t.diskErr.Truncated()
	m["log_truncated"] = truncated
	m["truncated"] = truncated
	if e != nil || ee != nil {
		m["log_error"] = fmt.Sprintf("stdout: %v; stderr: %v", e, ee)
	}
	return m
}

func (s *Service) loadHistory() {
	if s.stateDir == "" {
		return
	}
	dirs, e := os.ReadDir(filepath.Join(s.stateDir, "jobs"))
	if e != nil {
		return
	}
	for _, d := range dirs {
		if !d.IsDir() || strings.ContainsAny(d.Name(), "/\\") {
			continue
		}
		dir := s.jobDir(d.Name())
		b, e := os.ReadFile(filepath.Join(dir, "result.json"))
		if e != nil {
			continue
		}
		var rec jobRecord
		if json.Unmarshal(b, &rec) != nil || rec.ID != d.Name() {
			continue
		}
		t := &task{id: rec.ID, kind: "job", logDir: dir, started: rec.Started, finished: rec.Finished, exitCode: rec.ExitCode, timedOut: rec.TimedOut, interrupted: rec.Interrupted, logTruncated: rec.LogTruncated, done: make(chan struct{}), kill: func() {}}
		if rec.Running {
			t.interrupted = true
			t.exitCode = 130
			t.finished = time.Now()
			_ = s.persist(t, false)
		}
		close(t.done)
		s.tasks[t.id] = t
	}
}
