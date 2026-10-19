// Package audit appends one JSON line per remote operation to the state
// directory, so that unattended agent activity can be reviewed afterwards.
// Script text and arguments are recorded (truncated); stdin data is not.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxSize is the size at which audit.jsonl is rotated to audit.jsonl.1.
const MaxSize = 10 << 20

const maxArg = 512

type Entry struct {
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"` // connect, disconnect, tool, exec
	Conn       string    `json:"conn,omitempty"`
	User       string    `json:"user,omitempty"`
	Args       []string  `json:"args,omitempty"`
	ExitCode   *int      `json:"exit_code,omitempty"`
	Error      string    `json:"error,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// Log is safe for concurrent use; a nil *Log records nothing.
type Log struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func Open(dir string) (*Log, error) {
	l := &Log{path: filepath.Join(dir, "audit.jsonl")}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

func (l *Log) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *Log) Write(e Entry) {
	if l == nil {
		return
	}
	for i, a := range e.Args {
		e.Args[i] = Truncate(a, maxArg)
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if l.size+int64(len(b)) > MaxSize {
		l.f.Close()
		_ = os.Rename(l.path, l.path+".1")
		if l.open() != nil {
			l.f = nil
			return
		}
	}
	if n, err := l.f.Write(b); err == nil {
		l.size += int64(n)
	}
}

func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Truncate shortens s to at most n bytes on a UTF-8 boundary, noting the
// original length.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("…(%d bytes)", len(s))
}

// Code returns a pointer for Entry.ExitCode.
func Code(n int) *int { return &n }
