package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTruncateAndRotate(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	l.Write(Entry{Kind: "tool", Args: []string{"run", strings.Repeat("中", 400)}, ExitCode: Code(7)})
	var nilLog *Log
	nilLog.Write(Entry{Kind: "tool"})
	f, _ := os.Open(filepath.Join(dir, "audit.jsonl"))
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("no entry")
	}
	var e Entry
	if err := json.Unmarshal(scanner.Bytes(), &e); err != nil || e.Kind != "tool" || *e.ExitCode != 7 {
		t.Fatal(e, err)
	}
	if !strings.HasSuffix(e.Args[1], "(1200 bytes)") || len(e.Args[1]) > maxArg+20 {
		t.Fatalf("argument not truncated: %d", len(e.Args[1]))
	}
	f.Close()
	big := strings.Repeat("x", maxArg)
	for i := 0; i < MaxSize/maxArg+10; i++ {
		l.Write(Entry{Kind: "tool", Args: []string{big}})
	}
	l.Close()
	if st, err := os.Stat(filepath.Join(dir, "audit.jsonl.1")); err != nil || st.Size() > MaxSize {
		t.Fatal("not rotated", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "audit.jsonl")); st.Size() >= MaxSize {
		t.Fatal("current log not restarted")
	}
}
