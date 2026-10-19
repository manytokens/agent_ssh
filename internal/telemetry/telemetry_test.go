package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMetricsCountBothDirections(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	m := &Metrics{}
	wrapped := Wrap(l, m)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := wrapped.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 2)
		io.ReadFull(c, b)
		c.Write([]byte("done"))
	}()
	c, err := net.Dial("tcp4", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hi"))
	io.ReadFull(c, make([]byte, 4))
	<-done
	if m.Read.Load() != 2 || m.Written.Load() != 4 {
		t.Fatal("incorrect byte counters")
	}
}
func TestEventsWriteAndDeliverWithoutBlockingState(t *testing.T) {
	got := make(chan Event, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event Event
		json.NewDecoder(r.Body).Decode(&event)
		got <- event
		w.WriteHeader(204)
	}))
	defer server.Close()
	p := filepath.Join(t.TempDir(), "events.jsonl")
	events, err := NewEvents(context.Background(), p, server.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	events.Emit(Event{Phase: "online", Port: 22224})
	select {
	case event := <-got:
		if event.ID == "" || event.Phase != "online" {
			t.Fatal(event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("missing webhook")
	}
	if err := events.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(b, &event); err != nil || event.Port != 22224 {
		t.Fatalf("%s %v", b, err)
	}
}
func TestForwardingFailureIsNotAssumedToBePortCollision(t *testing.T) {
	if Classify("remote port forwarding failed for listen port 22222") != "forwarding_rejected" {
		t.Fatal("ambiguous forwarding error mislabeled")
	}
	if Classify("Permission denied (publickey)") != "authentication_rejected" {
		t.Fatal("missing auth classification")
	}
	if Classify("REMOTE HOST IDENTIFICATION HAS CHANGED") != "host_key_verification" {
		t.Fatal("missing host key classification")
	}
}
