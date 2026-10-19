package sysinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
)

func TestDiscoveryAndClipboardOptIn(t *testing.T) {
	s := Service{WorkDir: t.TempDir()}
	var out bytes.Buffer
	if err := s.Handle(context.Background(), []string{"info", "--json"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v["cwd"] != s.WorkDir || v["identity"] == nil || v["tools"] == nil || v["docker_engine"] == nil {
		t.Fatalf("discovery %s", out.String())
	}
	if err := s.Handle(context.Background(), []string{"clip", "set"}, bytes.NewBufferString("do not set"), io.Discard, io.Discard); err == nil {
		t.Fatal("clipboard enabled without opt-in")
	}
	if err := s.Handle(context.Background(), []string{"clip", "set", "--dry-run"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}
