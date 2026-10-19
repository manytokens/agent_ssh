package toolrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"agent_ssh/internal/toolproto"
	appversion "agent_ssh/internal/version"
)

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

var toolNames = []string{"command", "run", "put", "get", "ls", "hash", "info", "fs", "session", "job", "ps", "ports", "clip", "status"}

func toolsList() []any {
	var result []any
	for _, name := range toolNames {
		properties := map[string]any{"argv": map[string]any{"type": "array", "items": map[string]string{"type": "string"}}, "stdin_base64": map[string]string{"type": "string"}, "dry_run": map[string]any{"type": "boolean", "description": "Return an operation plan without executing scripts or changing target files."}}
		if name == "put" || name == "get" || name == "ls" || name == "hash" {
			properties["path"] = map[string]string{"type": "string", "description": "Native absolute or relative path on the connected computer; argv supplies optional flags."}
		}
		if name == "run" {
			properties["command"] = map[string]string{"type": "string", "description": "PowerShell source on Windows, shell source on Unix. argv supplies optional flags."}
		}
		result = append(result, map[string]any{"name": name, "description": "Execute assh " + name + " on the connected computer. argv contains individual arguments; stdin_base64 supplies binary input. stdout_base64 carries the exact bytes when binary is true (8 MiB limit per stream; get supports --offset/--size). Use command with [help] to discover syntax. put/get use native filesystem paths on the connected computer.", "inputSchema": map[string]any{"type": "object", "properties": properties, "additionalProperties": false}})
	}
	return result
}

// cappedBuffer drains excess output instead of letting a child block or consuming
// unbounded RAM. The result explicitly reports truncation. The buffer is a
// named field, not embedded: an embedded bytes.Buffer would export ReadFrom,
// which io.Copy (used by os/exec for stdout) prefers over the capped Write.
type cappedBuffer struct {
	buf       bytes.Buffer
	truncated bool
}

const outputCap = 8 * 1024 * 1024

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	room := outputCap - b.buf.Len()
	if len(p) > room {
		p = p[:room]
		b.truncated = true
	}
	_, err := b.buf.Write(p)
	return n, err
}
func (b *cappedBuffer) Len() int       { return b.buf.Len() }
func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }

// ServeMCP speaks newline-delimited JSON-RPC on stdout. Blocking input must
// implement io.ReadCloser whose Close interrupts Read; cancellation takes
// ownership of closing it. Finite in-memory readers need no Close method.
// Tool diagnostics and binary data are carried inside the response.
func ServeMCP(ctx context.Context, in io.Reader, out, stderr io.Writer, handler toolproto.Handler) error {
	parent := ctx
	if err := ctx.Err(); err != nil {
		return err
	}
	// Inherited Unix standard streams can be blocking descriptors that Go's
	// poller does not manage. Wrap them before installing cancellation hooks.
	if f, ok := in.(*os.File); ok {
		prepared, cleanup, err := prepareMCPFile(f)
		if err != nil {
			return err
		}
		defer cleanup()
		in = prepared
	}
	if f, ok := out.(*os.File); ok {
		prepared, cleanup, err := prepareMCPFile(f)
		if err != nil {
			return err
		}
		defer cleanup()
		out = prepared
	}
	// Transport shutdown closes blocked reads/writes; worker cancellation at
	// normal EOF must leave the SSH channel open for its exit-status message.
	transportCtx, closeTransport := context.WithCancel(ctx)
	defer closeTransport()
	ctx, cancel := context.WithCancel(transportCtx)
	defer cancel()
	stopInput, err := interruptMCPInput(transportCtx, in)
	if err != nil {
		return err
	}
	defer stopInput()
	stopOutput := func() {}
	if closer, ok := out.(io.Closer); ok {
		stopOutput = closeMCPOnCancellation(transportCtx, closer)
	}
	defer stopOutput()
	var outputMu, activeMu sync.Mutex
	var writeErr error
	active := map[string]context.CancelFunc{}
	var workers sync.WaitGroup
	write := func(id json.RawMessage, result any, code int, message string) {
		response := map[string]any{"jsonrpc": "2.0", "id": id}
		if code != 0 {
			response["error"] = map[string]any{"code": code, "message": message}
		} else {
			response["result"] = result
		}
		outputMu.Lock()
		defer outputMu.Unlock()
		if err := json.NewEncoder(out).Encode(response); err != nil {
			if writeErr == nil && ctx.Err() == nil {
				writeErr = err
			}
			fmt.Fprintln(stderr, "assh mcp:", err)
			closeTransport()
		}
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 16*1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			write(json.RawMessage("null"), nil, -32700, "Parse error")
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			write(json.RawMessage("null"), nil, -32600, "Invalid Request")
			continue
		}
		if len(req.ID) > 0 {
			var id any
			if err := json.Unmarshal(req.ID, &id); err != nil {
				write(json.RawMessage("null"), nil, -32600, "Invalid Request ID")
				continue
			}
			switch id.(type) {
			case string, float64, nil:
			default:
				write(json.RawMessage("null"), nil, -32600, "Invalid Request ID")
				continue
			}
		}
		if req.Method == "notifications/cancelled" {
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			_ = json.Unmarshal(req.Params, &p)
			activeMu.Lock()
			stop := active[string(p.RequestID)]
			activeMu.Unlock()
			if stop != nil {
				stop()
			}
			continue
		}
		if len(req.ID) == 0 {
			continue
		}
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				write(req.ID, nil, -32602, "Invalid initialize parameters")
				continue
			}
			version := "2024-11-05"
			if p.ProtocolVersion == "2025-03-26" || p.ProtocolVersion == "2025-06-18" || p.ProtocolVersion == "2025-11-25" {
				version = p.ProtocolVersion
			}
			write(req.ID, map[string]any{"protocolVersion": version, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "assh", "version": appversion.Version}, "instructions": "Tools execute as the connected local user. Windows run uses PowerShell. Query command argv=[help] and info before work. Binary streams use base64. Dry-run previews operations without executing shell code."}, 0, "")
		case "ping":
			write(req.ID, map[string]any{}, 0, "")
		case "tools/list":
			write(req.ID, map[string]any{"tools": toolsList()}, 0, "")
		case "tools/call":
			var p struct {
				Name      string `json:"name"`
				Arguments struct {
					Argv    []string `json:"argv"`
					Stdin   *string  `json:"stdin_base64"`
					Path    string   `json:"path"`
					Command string   `json:"command"`
					DryRun  bool     `json:"dry_run"`
				} `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				write(req.ID, nil, -32602, "Invalid tool arguments")
				continue
			}
			known := false
			for _, name := range toolNames {
				if p.Name == name {
					known = true
				}
			}
			if !known {
				write(req.ID, nil, -32602, "Unknown tool")
				continue
			}
			// put writes stdin to the target; a missing field must not mean "empty file".
			if p.Name == "put" && p.Arguments.Stdin == nil && !p.Arguments.DryRun {
				write(req.ID, nil, -32602, "put requires stdin_base64 (use \"\" for an empty file)")
				continue
			}
			var input []byte
			if p.Arguments.Stdin != nil {
				var err error
				if input, err = base64.StdEncoding.DecodeString(*p.Arguments.Stdin); err != nil {
					write(req.ID, nil, -32602, "Invalid stdin_base64")
					continue
				}
			}
			args := p.Arguments.Argv
			if p.Arguments.Path != "" {
				args = append([]string{p.Arguments.Path}, args...)
			}
			if p.Arguments.Command != "" {
				args = append(args, p.Arguments.Command)
			}
			if p.Name == "ls" || p.Name == "hash" {
				args = append([]string{"fs", p.Name}, args...)
			} else if p.Name != "command" {
				args = append([]string{p.Name}, args...)
			}
			if p.Arguments.DryRun {
				args = append([]string{"dry-run"}, args...)
			}
			key := string(req.ID)
			child, stop := context.WithCancel(ctx)
			activeMu.Lock()
			_, duplicate := active[key]
			if !duplicate {
				active[key] = stop
			}
			activeMu.Unlock()
			if duplicate {
				stop()
				write(req.ID, nil, -32600, "Request ID is already active")
				continue
			}
			workers.Add(1)
			go func(id json.RawMessage, args []string, input []byte, key string) {
				defer workers.Done()
				started := time.Now()
				defer stop()
				defer func() { activeMu.Lock(); delete(active, key); activeMu.Unlock() }()
				var stdout, errout cappedBuffer
				err := handler(child, args, bytes.NewReader(input), &stdout, &errout)
				// MCP: a cancelled request gets no response. The same applies when
				// stdin EOF closed the transport. Either way a result would read as
				// success, because the killed process exited without output.
				if child.Err() != nil {
					return
				}
				if err != nil && errout.Len() == 0 {
					fmt.Fprintln(&errout, err)
				}
				textOut := strings.ToValidUTF8(stdout.String(), "\ufffd")
				binary := !utf8.Valid(stdout.Bytes())
				result := map[string]any{"stdout": textOut, "stderr": strings.ToValidUTF8(errout.String(), "\ufffd"), "exit_code": toolproto.ExitCode(err), "duration": time.Since(started).Seconds(), "truncated": stdout.truncated || errout.truncated, "binary": binary}
				// Text output is exact in stdout; base64 is only needed for bytes JSON cannot carry.
				if binary {
					result["stdout_base64"] = base64.StdEncoding.EncodeToString(stdout.Bytes())
				}
				encoded, _ := json.Marshal(result)
				write(id, map[string]any{"content": []any{map[string]any{"type": "text", "text": string(encoded)}}, "structuredContent": result, "isError": err != nil}, 0, "")
			}(req.ID, args, input, key)
		default:
			write(req.ID, nil, -32601, "Method not found")
		}
	}
	// EOF closes the transport, including outstanding watches or jobs attached to it.
	scanErr, cancelErr := scanner.Err(), ctx.Err()
	stopInput()
	cancel()
	workers.Wait()
	stopOutput()
	if err := parent.Err(); err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	if cancelErr != nil {
		return cancelErr
	}
	return scanErr
}

// Cancel the actual transport read instead of abandoning a scanner goroutine.
// Waiting for the cancellation callback also prevents it from closing an input
// that a caller has already reclaimed after ServeMCP returns.
func interruptMCPInput(ctx context.Context, in io.Reader) (func(), error) {
	if closer, ok := in.(io.ReadCloser); ok {
		return closeMCPOnCancellation(ctx, closer), nil
	}
	switch in.(type) {
	case *bytes.Reader, *bytes.Buffer, *strings.Reader:
		return func() {}, nil
	default:
		return nil, errors.New("MCP blocking input must implement io.ReadCloser so cancellation can interrupt Read")
	}
}

func closeMCPOnCancellation(ctx context.Context, closer io.Closer) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = closer.Close(); close(done) })
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}
