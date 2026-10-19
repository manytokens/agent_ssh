package toolrpc

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

type signaledMCPInput struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (r *signaledMCPInput) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.ReadCloser.Read(p)
}

func TestMCPIdleCancellationInterruptsInput(t *testing.T) {
	for i := 0; i < 10; i++ {
		in, input := io.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		reader := &signaledMCPInput{ReadCloser: in, started: make(chan struct{})}
		done := make(chan error, 1)
		go func() { done <- ServeMCP(ctx, reader, io.Discard, io.Discard, nil) }()
		select {
		case <-reader.started:
		case <-time.After(time.Second):
			cancel()
			input.Close()
			t.Fatal("scanner did not start")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		case <-time.After(time.Second):
			input.Close()
			t.Fatal("idle scanner did not exit")
		}
		in.Close()
		input.Close()
	}
}

func TestMCPStdinCancellation(t *testing.T) {
	if os.Getenv("ASSH_MCP_CANCEL_TEST") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		if err := ServeMCP(ctx, os.Stdin, io.Discard, io.Discard, nil); !errors.Is(err, context.DeadlineExceeded) {
			os.Exit(2)
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMCPStdinCancellation$")
	cmd.Env = append(os.Environ(), "ASSH_MCP_CANCEL_TEST=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stdin cancellation failed: %v %s", err, output)
	}
}

func TestMCPIdleDeadline(t *testing.T) {
	in, input := io.Pipe()
	defer input.Close()
	defer in.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeMCP(ctx, in, io.Discard, io.Discard, nil) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lost deadline: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not interrupt input")
	}
}

type brokenMCPWriter struct{ err error }

func (w brokenMCPWriter) Write([]byte) (int, error) { return 0, w.err }

type signaledMCPOutput struct {
	io.WriteCloser
	started chan struct{}
	once    sync.Once
}

func (w *signaledMCPOutput) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	return w.WriteCloser.Write(p)
}

func TestMCPCancellationInterruptsBlockedOutput(t *testing.T) {
	in, input := io.Pipe()
	defer input.Close()
	defer in.Close()
	output, out := io.Pipe()
	defer output.Close()
	defer out.Close()
	writer := &signaledMCPOutput{WriteCloser: out, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- ServeMCP(ctx, in, writer, io.Discard, func(context.Context, []string, io.Reader, io.Writer, io.Writer) error { return nil })
	}()
	if _, err := io.WriteString(input, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"command\"}}\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("output write did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked output prevented cancellation")
	}
}

func TestMCPOutputFailureInterruptsIdleInput(t *testing.T) {
	in, input := io.Pipe()
	defer input.Close()
	defer in.Close()
	want := errors.New("output disconnected")
	done := make(chan error, 1)
	go func() {
		done <- ServeMCP(context.Background(), in, brokenMCPWriter{want}, io.Discard, func(context.Context, []string, io.Reader, io.Writer, io.Writer) error { return nil })
	}()
	if _, err := io.WriteString(input, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"command\",\"arguments\":{\"argv\":[\"ping\"]}}}\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("lost write error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("output failure left scanner blocked")
	}
}

type uninterruptibleMCPReader struct{}

func (uninterruptibleMCPReader) Read([]byte) (int, error) {
	panic("unsupported reader must be rejected before reading")
}
func TestMCPRejectsUninterruptibleInput(t *testing.T) {
	err := ServeMCP(context.Background(), uninterruptibleMCPReader{}, io.Discard, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "io.ReadCloser") {
		t.Fatalf("unsupported input accepted: %v", err)
	}
}
