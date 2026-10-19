package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agent_ssh/internal/localssh"
	"agent_ssh/internal/state"
	"agent_ssh/internal/sysinfo"
	"agent_ssh/internal/toolproto"
	"agent_ssh/internal/tools"
)

type toolFrame struct {
	Stream string `json:"stream"`
	Data   []byte `json:"data,omitempty"`
	Code   int    `json:"exit_code,omitempty"`
	Error  string `json:"error,omitempty"`
}
type frameWriter struct {
	mu       *sync.Mutex
	encoder  *json.Encoder
	response http.ResponseWriter
	stream   string
}

func (w frameWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.encoder.Encode(toolFrame{Stream: w.stream, Data: p})
	if f, ok := w.response.(http.Flusher); ok {
		f.Flush()
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func registerToolControl(mux *http.ServeMux, handler toolproto.Handler) {
	mux.HandleFunc("POST /tool", func(w http.ResponseWriter, r *http.Request) {
		var args []string
		b, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Assh-Args"))
		if err == nil {
			err = json.Unmarshal(b, &args)
		}
		if err != nil {
			http.Error(w, "invalid tool arguments", 400)
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.EnableFullDuplex()
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-store")
		var mu sync.Mutex
		e := json.NewEncoder(w)
		out := frameWriter{&mu, e, w, "stdout"}
		stderr := frameWriter{&mu, e, w, "stderr"}
		// The body is the tool's stdin. A tool may finish while its stdin copier
		// is still blocked reading the body; that read must end before the
		// handler returns, or it races the server reading the next request.
		in, pipe := io.Pipe()
		pumped := make(chan struct{})
		go func() {
			defer close(pumped)
			_, e := io.Copy(pipe, r.Body)
			pipe.CloseWithError(e)
		}()
		err = handler(r.Context(), args, in, out, stderr)
		in.Close()
		_ = rc.SetReadDeadline(time.Now())
		<-pumped
		mu.Lock()
		defer mu.Unlock()
		result := toolFrame{Stream: "result", Code: toolproto.ExitCode(err)}
		if err != nil {
			result.Error = err.Error()
		}
		_ = e.Encode(result)
	})
}

func isToolVerb(v string) bool {
	if strings.HasPrefix(v, "--timeout=") {
		return true
	}
	switch v {
	case "exec", "bash", "wsl", "fs", "put", "get", "sync", "session", "job", "watch", "info", "ps", "ports", "clip", "capabilities", "connection", "mcp", "dry-run", "--dry-run", "--timeout", "--json":
		return true
	}
	return false
}

func toolMain(args []string) error {
	dir, err := state.DefaultDir()
	if err != nil {
		return err
	}
	var clean []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--state-dir" {
			if i+1 == len(args) {
				return errors.New("--state-dir needs a directory")
			}
			i++
			dir = args[i]
		} else if strings.HasPrefix(args[i], "--state-dir=") {
			dir = strings.TrimPrefix(args[i], "--state-dir=")
		} else {
			clean = append(clean, args[i])
		}
	}
	dir, err = absolutePath(dir)
	if err != nil {
		return err
	}
	args = clean
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if _, err = getStatus(dir); err == nil {
		return callToolControl(ctx, dir, args, os.Stdin, os.Stdout, os.Stderr)
	}
	if len(args) > 0 && (args[0] == "session" || args[0] == "job") {
		return errors.New("start an assh service before using persistent sessions/jobs")
	}
	shell, err := localssh.ResolveShell("")
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// A standalone MCP process owns a separate job store. It must never load
	// another service's active jobs or mark them interrupted.
	store := ""
	if len(args) > 0 && args[0] == "mcp" {
		store = filepath.Join(dir, "mcp", strconv.Itoa(os.Getpid()))
	}
	s := tools.New(tools.Config{Shell: shell, WorkDir: cwd, StateDir: store})
	defer s.Close()
	return s.Handle(ctx, args, os.Stdin, os.Stdout, os.Stderr)
}

func callToolControl(ctx context.Context, dir string, args []string, in io.Reader, out, stderr io.Writer) error {
	var rt runtimeFile
	if err := state.ReadJSON(filepath.Join(dir, "runtime.json"), &rt); err != nil {
		return err
	}
	u, err := url.Parse("http://" + rt.Address)
	if err != nil || u.Hostname() != "127.0.0.1" {
		return errors.New("invalid control listener address")
	}
	b, _ := json.Marshal(args)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String()+"/tool", in)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+rt.Token)
	req.Header.Set("X-Assh-Args", base64.StdEncoding.EncodeToString(b))
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("tool control: %s", resp.Status)
	}
	d := json.NewDecoder(resp.Body)
	for {
		var f toolFrame
		if err := d.Decode(&f); err != nil {
			return err
		}
		switch f.Stream {
		case "stdout":
			if _, err = out.Write(f.Data); err != nil {
				return err
			}
		case "stderr":
			if _, err = stderr.Write(f.Data); err != nil {
				return err
			}
		case "result":
			if f.Code != 0 {
				if f.Error != "" {
					fmt.Fprintln(stderr, f.Error)
				}
				return toolproto.ExitError{Code: f.Code}
			}
			return nil
		}
	}
}

func localIdentity() map[string]string { return sysinfo.Identity() }
func validateWebhook(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("--event-webhook requires an HTTP(S) URL")
	}
	return nil
}
