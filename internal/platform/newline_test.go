package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestConsoleNewlinesReturnToColumnZero(t *testing.T) {
	var output bytes.Buffer
	w := consoleNewlines{out: &output}
	input := []byte("assh: error\nnext\r\n中文\n")
	n, err := w.Write(input)
	if err != nil || n != len(input) || output.String() != "assh: error\r\nnext\r\n中文\r\n" {
		t.Fatalf("%q n=%d err=%v", output.String(), n, err)
	}
}

func TestRedirectedOutputPreservesBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("{\n  \"phase\": \"stopped\"\n}\n")
	_, err = ConsoleWriter(f).Write(input)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("redirect changed bytes: %q %v", got, err)
	}
}
