package filesvc

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func TestTarDownloadRejectsRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("keep this content"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(root)
	defer s.Close()
	for _, args := range [][]string{
		{"get", "file", "--tar"}, {"get", "file", "--tar", "--dry-run"},
		{"fs", "tar-get", "file"}, {"fs", "tar-get", "file", "--dry-run"},
	} {
		var out bytes.Buffer
		err := s.Handle(context.Background(), args, nil, &out, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "not a directory") || out.Len() != 0 {
			t.Fatalf("%v: err=%v output=%d bytes", args, err, out.Len())
		}
	}
}

func TestSyncEmptyRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	s := New(root)
	call(t, s, nil, "sync", "empty", "dry-destination", "--dry-run")
	if _, err := os.Stat(filepath.Join(root, "dry-destination")); !os.IsNotExist(err) {
		t.Fatalf("dry-run created destination: %v", err)
	}
	call(t, s, nil, "sync", "empty", "destination")
	if info, err := os.Stat(filepath.Join(root, "destination")); err != nil || !info.IsDir() {
		t.Fatalf("empty destination missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Handle(context.Background(), []string{"sync", "empty", "file"}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted a file as destination directory")
	}
}
func call(t *testing.T, s *Service, data []byte, args ...string) []byte {
	t.Helper()
	if len(args) > 1 && args[0] == "fs" && (args[1] == "stage" || args[1] == "write" || args[1] == "commit") {
		args = append(args, "--transfer-id", t.Name())
	}
	var out bytes.Buffer
	if e := s.Handle(context.Background(), args, bytes.NewReader(data), &out, io.Discard); e != nil {
		t.Fatal(args, e)
	}
	return out.Bytes()
}
func TestChunkResumeVerificationAndAtomicCommit(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	t.Cleanup(func() { s.Close() })
	content := bytes.Repeat([]byte("x"), 8192)
	content = append(content, []byte("tail")...)
	call(t, s, nil, "fs", "stage", "中文.bin", "--size", strconv.Itoa(len(content)), "--block-size", "4096")
	call(t, s, content[:4096], "fs", "write", "中文.bin", "--offset", "0", "--size", "4096", "--sha256", digest(content[:4096]))
	// Resuming preserves and verifies each actual .part block rather than trusting progress metadata.
	var resumed struct {
		Blocks []string `json:"blocks"`
	}
	json.Unmarshal(call(t, s, nil, "fs", "stage", "中文.bin", "--size", strconv.Itoa(len(content)), "--block-size", "4096"), &resumed)
	if resumed.Blocks[0] != digest(content[:4096]) || resumed.Blocks[1] == digest(content[4096:8192]) {
		t.Fatal("resume did not inspect actual chunks", resumed)
	}
	if e := s.Handle(context.Background(), []string{"fs", "write", "中文.bin", "--offset", "4096", "--size", "4096", "--sha256", digest([]byte("bad")), "--transfer-id", t.Name()}, bytes.NewReader(content[4096:8192]), io.Discard, io.Discard); e == nil {
		t.Fatal("bad chunk accepted")
	}
	if e := s.Handle(context.Background(), []string{"fs", "commit", "中文.bin", "--sha256", digest(content), "--transfer-id", t.Name()}, nil, io.Discard, io.Discard); e == nil {
		t.Fatal("incomplete commit accepted")
	}
	if _, e := os.Stat(filepath.Join(dir, "中文.bin")); !os.IsNotExist(e) {
		t.Fatal("destination exists before commit")
	}
	call(t, s, content[4096:], "fs", "write", "中文.bin", "--offset", "4096", "--size", strconv.Itoa(len(content)-4096), "--sha256", digest(content[4096:]))
	call(t, s, nil, "fs", "commit", "中文.bin", "--sha256", digest(content))
	if got := call(t, s, nil, "get", "中文.bin"); !bytes.Equal(got, content) {
		t.Fatal("binary roundtrip mismatch")
	}
	// A changed destination on the next transfer is seeded and rehashed.
	os.WriteFile(filepath.Join(dir, "中文.bin"), []byte("changed"), 0600)
	var next struct {
		Blocks []string `json:"blocks"`
	}
	json.Unmarshal(call(t, s, nil, "fs", "stage", "中文.bin", "--size", "7", "--block-size", "4096"), &next)
	if next.Blocks[0] != digest([]byte("changed")) {
		t.Fatal("changed destination not seeded")
	}
}
func TestDryRunTextAndTar(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if e := s.Handle(context.Background(), []string{"put", "missing", "--tar", "--dry-run"}, rejectReader{}, io.Discard, io.Discard); e != nil {
		t.Fatal("tar dry-run read stdin", e)
	}
	for _, args := range [][]string{{"put", "missing/file", "--dry-run"}, {"fs", "stage", "missing/file", "--size", "5", "--dry-run"}, {"fs", "write", "missing/file", "--size", "5", "--dry-run"}, {"fs", "commit", "missing/file", "--dry-run"}, {"watch", "missing", "--dry-run"}} {
		call(t, s, []byte("hello"), args...)
	}
	if ds, _ := os.ReadDir(dir); len(ds) != 0 {
		t.Fatal("dry-run wrote files")
	}
	input := []byte("中文\r\na\rb\n")
	expected := []byte("中文\na\rb\n")
	call(t, s, input, "put", "text", "--text", "--sha256", digest(expected))
	if got := call(t, s, nil, "get", "text"); !bytes.Equal(got, expected) {
		t.Fatalf("text mismatch %q", got)
	}
	call(t, s, input, "put", "binary")
	if got := call(t, s, nil, "get", "binary"); !bytes.Equal(got, input) {
		t.Fatal("default binary transformed")
	}
	archive := call(t, s, nil, "get", ".", "--tar")
	call(t, s, archive, "put", "unpacked", "--tar")
	got, e := os.ReadFile(filepath.Join(dir, "unpacked", "binary"))
	if e != nil || !bytes.Equal(got, input) {
		t.Fatal("tar roundtrip", e)
	}
	var unsafe bytes.Buffer
	tw := tar.NewWriter(&unsafe)
	tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0600, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	if e = s.Handle(context.Background(), []string{"put", "bad", "--tar"}, &unsafe, io.Discard, io.Discard); e == nil {
		t.Fatal("tar traversal accepted")
	}
}

type rejectReader struct{}

func (rejectReader) Read([]byte) (int, error) { panic("dry-run must not read stdin") }
func TestSyncOnlyChangesAndExcludes(t *testing.T) {
	if !excluded("中文/临时.tmp", false, []string{"中文/**"}) {
		t.Fatal("Unicode exclude did not match")
	}
	dir := t.TempDir()
	s := New(dir)
	os.MkdirAll(filepath.Join(dir, "src", "build"), 0755)
	os.MkdirAll(filepath.Join(dir, "dst"), 0755)
	a := bytes.Repeat([]byte("a"), 4096)
	b := bytes.Repeat([]byte("b"), 4096)
	src := append(append([]byte{}, a...), b...)
	dst := append(append([]byte{}, a...), a...)
	os.WriteFile(filepath.Join(dir, "src", "f"), src, 0600)
	os.WriteFile(filepath.Join(dir, "dst", "f"), dst, 0600)
	os.WriteFile(filepath.Join(dir, "src", "build", "skip.tmp"), []byte("skip"), 0600)
	os.WriteFile(filepath.Join(dir, "src", "build", "keep.txt"), []byte("keep"), 0600)
	args := []string{"sync", "src", "dst", "--block-size", "4096", "--exclude", "build/", "--exclude", "!build/keep.txt"}
	var plan syncResult
	json.Unmarshal(call(t, s, nil, append(args, "--dry-run")...), &plan)
	if plan.ChangedBlocks != 2 || plan.TransferredBytes != 4100 {
		t.Fatal(plan)
	}
	still, _ := os.ReadFile(filepath.Join(dir, "dst", "f"))
	if !bytes.Equal(still, dst) {
		t.Fatal("dry-run modified target")
	}
	// An abandoned unrelated .part cannot corrupt unchanged portions of local sync.
	os.WriteFile(filepath.Join(dir, "dst", "f.part"), bytes.Repeat([]byte("z"), 8192), 0600)
	var actual syncResult
	json.Unmarshal(call(t, s, nil, args...), &actual)
	if actual.ChangedBlocks != plan.ChangedBlocks {
		t.Fatal(actual)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "dst", "f"))
	if !bytes.Equal(got, src) {
		t.Fatal("sync bytes wrong")
	}
	if _, e := os.Stat(filepath.Join(dir, "dst", "build", "skip.tmp")); !os.IsNotExist(e) {
		t.Fatal("exclude ignored")
	}
	var second syncResult
	json.Unmarshal(call(t, s, nil, args...), &second)
	if second.ChangedBlocks != 0 || second.TransferredBytes != 0 {
		t.Fatal("unchanged file retransferred", second)
	}
	os.WriteFile(filepath.Join(dir, "src", "text"), []byte("中文\r\nline\r\n"), 0600)
	call(t, s, nil, "sync", "src", "textdst", "--text", "--exclude", "build/")
	text, _ := os.ReadFile(filepath.Join(dir, "textdst", "text"))
	if string(text) != "中文\nline\n" {
		t.Fatal("sync --text did not normalize", string(text))
	}
}
func TestRecursiveWatchCancellation(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "child"), 0755)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- watch(ctx, dir, writer); writer.Close() }()
	decoder := json.NewDecoder(reader)
	var event map[string]any
	if e := decoder.Decode(&event); e != nil || event["event"] != "ready" {
		t.Fatal(event, e)
	}
	os.WriteFile(filepath.Join(dir, "child", "file"), []byte("x"), 0600)
	if e := decoder.Decode(&event); e != nil || !strings.Contains(event["path"].(string), "file") {
		t.Fatal(event, e)
	}
	reader.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not exit")
	}
}

func TestRejectsAmbiguousTargets(t *testing.T) {
	s := New(t.TempDir())
	dir := filepath.Join(s.Workdir, "dir")
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e := s.Handle(context.Background(), []string{"fs", "stage", dir, "--size", "1"}, nil, &out, io.Discard); e == nil {
		t.Fatal("staged a file over a directory")
	}
	if _, e := os.Stat(dir + ".part"); !os.IsNotExist(e) {
		t.Fatal("left a .part beside the directory")
	}
	if e := s.Handle(context.Background(), []string{"get", dir}, nil, &out, io.Discard); e == nil || !strings.Contains(e.Error(), "directory") {
		t.Fatal("get of a directory", e)
	}
	if e := s.Handle(context.Background(), []string{"watch", filepath.Join(dir, "..", "dir", "..", "missing-file")}, nil, &out, io.Discard); e == nil {
		t.Fatal("watched a missing path")
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"a:b", "trail.", "space ", "CON", "nul.txt", "x?y"} {
			if e := s.Handle(context.Background(), []string{"put", filepath.Join(dir, name)}, strings.NewReader("x"), &out, io.Discard); e == nil {
				t.Errorf("accepted Windows name %q", name)
			}
		}
		if left, _ := os.ReadDir(dir); len(left) > 0 {
			t.Errorf("rejected puts left files: %v", left)
		}
	}
	if e := s.Handle(context.Background(), []string{"fs", "stat", ""}, nil, &out, io.Discard); e == nil {
		t.Fatal("empty path accepted")
	}
	if runtime.GOOS == "windows" {
		if got := s.path("/c/Windows"); got != `C:\Windows` {
			t.Fatalf("drive spelling %q", got)
		}
	}
	var empty bytes.Buffer
	tw := tar.NewWriter(&empty)
	tw.Close()
	target := filepath.Join(s.Workdir, "empty-root")
	if e := s.Handle(context.Background(), []string{"put", target, "--tar"}, &empty, &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	if i, e := os.Stat(target); e != nil || !i.IsDir() {
		t.Fatal("empty directory upload did not create the root")
	}
}
