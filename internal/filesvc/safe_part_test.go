package filesvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func partDigest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func TestStagedFileLinksCannotModifyExternalData(t *testing.T) {
	for _, kind := range []string{"hardlink", "symlink"} {
		for _, operation := range []string{"stage", "write", "put", "commit", "open"} {
			t.Run(kind+"/"+operation, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "target")
				external := filepath.Join(dir, "external")
				original := []byte("important external data")
				if err := os.WriteFile(external, original, 0600); err != nil {
					t.Fatal(err)
				}
				link := os.Link
				if kind == "symlink" {
					link = os.Symlink
				}
				if err := link(external, target+".part"); err != nil {
					t.Skipf("link unavailable: %v", err)
				}
				var err error
				switch operation {
				case "stage":
					err = stage(target, options{size: 1, block: 1024}, io.Discard)
				case "write":
					err = writeChunk(target, options{size: 1, hash: partDigest([]byte("x"))}, bytes.NewBufferString("x"), io.Discard)
				case "put":
					err = put(context.Background(), target, options{}, bytes.NewBufferString("replacement"), io.Discard)
				case "commit":
					err = commit(target, options{hash: partDigest(original)}, io.Discard)
				case "open":
					var f *os.File
					f, err = openSafePart(target+".part", os.O_RDWR)
					if f != nil {
						f.Close()
					}
				}
				if err == nil {
					t.Fatalf("accepted %s staged file", kind)
				}
				got, readErr := os.ReadFile(external)
				if readErr != nil || !bytes.Equal(got, original) {
					t.Fatalf("external data changed: %q %v", got, readErr)
				}
				if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
					t.Fatalf("published rejected link: %v", statErr)
				}
			})
		}
	}
}

func TestSafeCommitHashMismatchRetainsPart(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	data := []byte("resumable")
	if err := os.WriteFile(target+".part", data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := commit(target, options{hash: partDigest([]byte("other"))}, io.Discard); err == nil {
		t.Fatal("accepted mismatch")
	}
	got, err := os.ReadFile(target + ".part")
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("lost resume: %q %v", got, err)
	}
	left, err := filepath.Glob(filepath.Join(dir, ".assh-commit-*"))
	if err != nil || len(left) != 0 {
		t.Fatal(left, err)
	}
	if err := commit(target, options{hash: partDigest(data)}, io.Discard); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(target)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal(string(got), err)
	}
}

func TestPackRejectsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	link := filepath.Join(dir, "link")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := pack(context.Background(), link, options{}, io.Discard); err == nil {
		t.Fatal("accepted symlink root")
	}
}
