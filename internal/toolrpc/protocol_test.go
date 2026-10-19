package toolrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"agent_ssh/internal/toolproto"
)

func TestToolExitCodesPreserveWrappedValueAndPointer(t *testing.T) {
	for _, err := range []error{toolproto.ExitError{Code: 7}, &toolproto.ExitError{Code: 7}, fmt.Errorf("wrapped: %w", toolproto.ExitError{Code: 7}), fmt.Errorf("wrapped: %w", &toolproto.ExitError{Code: 7})} {
		if got := toolproto.ExitCode(err); got != 7 {
			t.Fatalf("%T: got exit code %d", err, got)
		}
	}
	if toolproto.ExitCode(nil) != 0 || toolproto.ExitCode(context.Canceled) != 1 {
		t.Fatal("default exit codes")
	}
}

func TestArgumentTransport(t *testing.T) {
	args := []string{"run", "", "中文 $USER 'quoted'\nline", "D:\\some path\\x"}
	got, ok, err := Decode(Encode(args))
	if err != nil || !ok || !reflect.DeepEqual(args, got) {
		t.Fatalf("round trip: %#v %v %v", got, ok, err)
	}
	if _, ok, _ := Decode("Get-Location"); ok {
		t.Fatal("ordinary shell intercepted")
	}
	for _, value := range []string{"???", base64.StdEncoding.EncodeToString([]byte("missing terminator"))} {
		if _, ok, err := Decode(Prefix + value); !ok || err == nil {
			t.Fatal("malformed protocol accepted")
		}
	}
}

func TestMCPBinaryOutputAndCancellation(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	finished := make(chan error, 1)
	go func() {
		finished <- ServeMCP(context.Background(), inR, outW, io.Discard, func(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
			if args[0] == "watch" {
				<-ctx.Done()
				return ctx.Err()
			}
			if args[0] == "get" || args[0] == "dry-run" {
				_, err := fmt.Fprint(out, strings.Join(args, "|"))
				return err
			}
			data, _ := io.ReadAll(in)
			_, err := out.Write(data)
			return err
		})
	}()
	reader := bufio.NewReader(outR)
	read := func() map[string]any {
		t.Helper()
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err = json.Unmarshal(line, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if read()["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Fatal("version negotiation")
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"command","arguments":{"argv":["run"],"stdin_base64":"AP9B"}}}`)
	r := read()["result"].(map[string]any)["structuredContent"].(map[string]any)
	if r["stdout_base64"] != "AP9B" || r["binary"] != true {
		t.Fatalf("binary data changed: %v", r)
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get","arguments":{"path":"D:/中文/file","argv":["--offset","4","--size","8"]}}}`)
	if r := read()["result"].(map[string]any)["structuredContent"].(map[string]any); r["stdout"] != "get|D:/中文/file|--offset|4|--size|8" {
		t.Fatal(r)
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run","arguments":{"command":"Write-Output hello","dry_run":true}}}`)
	if r := read()["result"].(map[string]any)["structuredContent"].(map[string]any); r["stdout"] != "dry-run|run|Write-Output hello" {
		t.Fatal(r)
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"command","arguments":{"argv":["watch"]}}}`)
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":5,"method":"ping"}`)
	if read()["id"] != float64(5) {
		t.Fatal("long-running tool blocked ping")
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}`)
	// A cancelled request gets no response; the next line answers the ping.
	time.Sleep(100 * time.Millisecond)
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if r := read(); r["id"] != float64(7) {
		t.Fatalf("cancelled request answered: %v", r)
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"put","arguments":{"path":"D:/x"}}}`)
	if r := read(); r["error"] == nil {
		t.Fatalf("put without stdin_base64 accepted: %v", r)
	}
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"command","arguments":{"argv":["run"],"stdin_base64":"aGk="}}}`)
	if r := read()["result"].(map[string]any)["structuredContent"].(map[string]any); r["stdout"] != "hi" || r["stdout_base64"] != nil {
		t.Fatalf("text output: %v", r)
	}
	inW.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transport did not close")
	}
}

func TestMCPRejectsInvalidRequestsAndCapsOutput(t *testing.T) {
	var out bytes.Buffer
	input := "{bad}\n" + `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown"}}` + "\n"
	if err := ServeMCP(context.Background(), strings.NewReader(input), &out, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "-32700") || !strings.Contains(out.String(), "-32602") {
		t.Fatal(out.String())
	}
	var b cappedBuffer
	p := make([]byte, 9*1024*1024)
	n, err := b.Write(p)
	if err != nil || n != len(p) || b.Len() != 8*1024*1024 || !b.truncated {
		t.Fatal("output cap")
	}
	// os/exec copies child stdout with io.Copy, which must not bypass the cap.
	var c cappedBuffer
	if _, err := io.Copy(&c, bytes.NewReader(p)); err != nil || c.Len() != 8*1024*1024 || !c.truncated {
		t.Fatalf("io.Copy bypassed output cap: %d", c.Len())
	}
}

// A slow tool call must not delay others on the same MCP connection.
func TestMCPCallsRunConcurrently(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	release := make(chan struct{})
	go ServeMCP(context.Background(), inR, outW, io.Discard, func(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
		if args[len(args)-1] == "slow" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		_, err := fmt.Fprint(out, args[len(args)-1])
		return err
	})
	reader := bufio.NewReader(outR)
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{"command":"slow"}}}`)
	fmt.Fprintln(inW, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run","arguments":{"command":"fast"}}}`)
	got := make(chan map[string]any, 2)
	go func() {
		for i := 0; i < 2; i++ {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var r map[string]any
			_ = json.Unmarshal(line, &r)
			got <- r
		}
	}()
	select {
	case r := <-got:
		if r["id"] != float64(2) {
			t.Fatalf("fast call waited for the slow one: %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fast call blocked")
	}
	close(release)
	if r := <-got; r["id"] != float64(1) {
		t.Fatal(r)
	}
	inW.Close()
}
