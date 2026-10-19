package app

import (
	"agent_ssh/internal/audit"
	"agent_ssh/internal/state"
	"agent_ssh/internal/toolproto"
	"agent_ssh/internal/tools"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestToolControlAuditsLocalCLIOperation(t *testing.T) {
	dir := t.TempDir()
	log, err := audit.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	svc := tools.New(tools.Config{WorkDir: dir, Audit: log})
	defer svc.Close()
	mux := http.NewServeMux()
	registerToolControl(mux, svc.Handle)
	server := httptest.NewServer(mux)
	defer server.Close()
	if err := state.WriteJSON(filepath.Join(dir, "runtime.json"), runtimeFile{Address: server.Listener.Addr().String(), Token: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := callToolControl(context.Background(), dir, []string{"ping"}, bytes.NewReader(nil), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(log.Path())
	if err != nil {
		t.Fatal(err)
	}
	var entry audit.Entry
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil || len(entry.Args) != 1 || entry.Args[0] != "ping" || entry.ExitCode == nil || *entry.ExitCode != 0 {
		t.Fatalf("expected exactly one successful CLI audit entry: %s (%v)", data, err)
	}
}

func TestStreamingToolControlPreservesBinaryAndExitStatus(t *testing.T) {
	mux := http.NewServeMux()
	registerToolControl(mux, func(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
		if len(args) != 1 || args[0] != "test" {
			t.Error(args)
		}
		io.Copy(out, in)
		stderr.Write([]byte("separate"))
		return &toolproto.ExitError{Code: 7}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	dir := t.TempDir()
	if err := state.WriteJSON(filepath.Join(dir, "runtime.json"), runtimeFile{Address: server.Listener.Addr().String(), Token: "test"}); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	err := callToolControl(context.Background(), dir, []string{"test"}, bytes.NewReader([]byte{0, 255, 10}), &out, &stderr)
	if toolproto.ExitCode(err) != 7 || !bytes.Equal(out.Bytes(), []byte{0, 255, 10}) || !bytes.Contains(stderr.Bytes(), []byte("separate")) {
		t.Fatalf("%v %v %q", err, out.Bytes(), stderr.String())
	}
	// Invalid headers fail before the handler starts.
	r := httptest.NewRequest("POST", "/tool", nil)
	b, _ := json.Marshal("not argv")
	r.Header.Set("X-Assh-Args", base64.StdEncoding.EncodeToString(b))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
