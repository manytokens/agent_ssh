package execsvc

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestTaskTextPollingPreservesSplitUTF8(t *testing.T) {
	task := &task{kind: "session", done: make(chan struct{}), started: time.Now()}
	data := []byte("中")
	task.stdout.Write(data[:1])
	m := task.resultMemory(0)
	if m["stdout"] != "" || m["offset"] != int64(0) {
		t.Fatalf("consumed partial rune: %v", m)
	}
	task.stdout.Write(data[1:])
	m = task.resultMemory(m["offset"].(int64))
	if m["stdout"] != "中" || m["offset"] != int64(3) {
		t.Fatalf("lost split rune: %v", m)
	}
	// Raw attach must keep forwarding partial writes immediately.
	var raw logBuffer
	raw.Write(data[:1])
	got, next, _ := raw.snapshot(0)
	if got != string(data[:1]) || next != 1 {
		t.Fatal("raw terminal bytes changed")
	}
	// An incomplete final byte sequence is delivered with exact base64 bytes.
	task.stdout.Write([]byte{0xe4})
	close(task.done)
	m = task.resultMemory(3)
	if m["offset"] != int64(4) || m["stdout_base64"] != base64.StdEncoding.EncodeToString([]byte{0xe4}) {
		t.Fatalf("lost final bytes: %v", m)
	}
}
