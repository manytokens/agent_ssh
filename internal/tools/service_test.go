package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestGlobalOptionsPreserveNestedActions(t *testing.T) {
	for _, v := range []struct{ in, want []string }{
		{[]string{"dry-run", "fs", "mkdir", "missing"}, []string{"fs", "mkdir", "--dry-run", "missing"}},
		{[]string{"--json", "--timeout=2s", "run", "echo hi"}, []string{"run", "--json", "--timeout", "2s", "echo hi"}},
		{[]string{"--dry-run", "job", "kill", "id"}, []string{"job", "kill", "id", "--dry-run"}},
		{[]string{"--json", "session", "read", "id"}, []string{"session", "read", "id", "--json"}},
		{[]string{"--json", "--timeout=2s", "job", "wait", "id"}, []string{"job", "wait", "id", "--json", "--timeout", "2s"}},
		{[]string{"--json", "session", "send", "id", "echo hi"}, []string{"session", "send", "id", "--json", "echo hi"}},
		{[]string{"--timeout", "2", "echo hi"}, []string{"run", "--timeout", "2", "echo hi"}},
	} {
		got, err := Normalize(v.in)
		if err != nil || !reflect.DeepEqual(got, v.want) {
			t.Fatalf("%v -> %v, %v", v.in, got, err)
		}
	}
}
func TestDryRunDoesNotStartMCPOrCreateDirectories(t *testing.T) {
	root := t.TempDir()
	s := New(Config{WorkDir: root})
	defer s.Close()
	for _, args := range [][]string{{"dry-run", "mcp"}, {"dry-run", "fs", "mkdir", "missing"}, {"dry-run", "clip", "set"}} {
		var out bytes.Buffer
		if err := s.Handle(context.Background(), args, bytes.NewBufferString("do not write"), &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := json.Unmarshal(out.Bytes(), &v); err != nil || v["dry_run"] != true {
			t.Fatalf("%s: %v", out.String(), err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote a directory")
	}
}

func TestStatusReportsTunnelAndTasks(t *testing.T) {
	started := time.Now().Add(-time.Minute).UTC()
	svc := New(Config{WorkDir: t.TempDir(), StateDir: t.TempDir(), Connection: func() any {
		return map[string]any{"phase": "online", "reconnects": 2, "started_at": started, "online_since": started}
	}})
	defer svc.Close()
	var out bytes.Buffer
	if err := svc.Handle(context.Background(), []string{"status"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r["phase"] != "online" || r["reconnects"] != float64(2) || r["uptime_seconds"].(float64) < 59 || r["online_seconds"] == nil || r["sessions_running"] != float64(0) || r["jobs_running"] != float64(0) {
		t.Fatalf("status: %v", r)
	}
}
