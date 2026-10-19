package filesvc

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirectoryTransfersRespectMemberLocksAcrossServices(t *testing.T) {
	root := t.TempDir()
	first, second := New(root), New(root)
	defer first.Close()
	defer second.Close()
	if err := first.Handle(context.Background(), []string{"fs", "stage", "dest/file", "--size", "3", "--transfer-id", "A"}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	tw.WriteHeader(&tar.Header{Name: "file", Mode: 0600, Size: 3})
	tw.Write([]byte("bad"))
	tw.Close()
	err := second.Handle(context.Background(), []string{"put", "dest", "--tar"}, &archive, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("tar member bypassed lock: %v", err)
	}
	os.Mkdir(filepath.Join(root, "source"), 0700)
	os.WriteFile(filepath.Join(root, "source", "file"), []byte("bad"), 0600)
	err = second.Handle(context.Background(), []string{"sync", "source", "dest"}, nil, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("sync member bypassed lock: %v", err)
	}
	part, err := os.ReadFile(filepath.Join(root, "dest", "file.part"))
	if err != nil || !bytes.Equal(part, make([]byte, 3)) {
		t.Fatalf("staging bytes were modified: %v %v", part, err)
	}
}

func TestCloseKeepsActiveTransferLockedUntilItReturns(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	release, err := s.reserveWrite(filepath.Join(root, "file"), "A", "stage")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	other := New(root)
	defer other.Close()
	if unlock, err := other.reserveWrite(filepath.Join(root, "file"), "B", "stage"); err == nil {
		unlock(false)
		t.Fatal("close released active destination")
	}
	release(true)
	unlock, err := other.reserveWrite(filepath.Join(root, "file"), "B", "stage")
	if err != nil {
		t.Fatal("active destination never released:", err)
	}
	unlock(true)
}

func TestSyncRejectsOverlappingDirectories(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	defer s.Close()
	for _, args := range [][]string{
		{"sync", ".", "backup"}, {"sync", ".", ".", "--dry-run"},
		{"sync", ".", "backup", "--dry-run"},
	} {
		if err := s.Handle(context.Background(), args, nil, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("%v accepted overlapping directories: %v", args, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "backup")); !os.IsNotExist(err) {
		t.Fatal("rejected sync created destination")
	}
	if err := os.Mkdir(filepath.Join(root, "source"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Handle(context.Background(), []string{"sync", "source", "."}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted destination containing source")
	}
	t.Run("symlink-alias", func(t *testing.T) {
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(root, alias); err != nil {
			t.Skip(err)
		}
		err := s.Handle(context.Background(), []string{"sync", root, filepath.Join(alias, "nested")}, nil, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("alias bypassed overlap check: %v", err)
		}
	})
}

func TestTransferReservationProtectsWholeUpload(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	defer s.Close()
	request := func(service *Service, data []byte, args ...string) error {
		return service.Handle(context.Background(), args, bytes.NewReader(data), io.Discard, io.Discard)
	}
	stageA := []string{"fs", "stage", "file", "--size", "3", "--transfer-id", "A"}
	if err := request(s, nil, stageA...); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"fs", "stage", "file", "--size", "9", "--transfer-id", "B"},
		{"put", "file"}, {"put", "file.part"},
		{"fs", "write", "file", "--size", "3", "--offset", "0", "--sha256", digest([]byte("bad"))},
		{"fs", "write", "file", "--size", "3", "--offset", "0", "--sha256", digest([]byte("bad")), "--transfer-id", "B"},
		{"fs", "abort", "file", "--transfer-id", "B"},
	} {
		if err := request(s, []byte("bad"), args...); err == nil {
			t.Fatalf("conflict accepted: %v", args)
		}
	}
	// Independent service instances must also respect the OS destination lock.
	other := New(root)
	defer other.Close()
	if err := request(other, nil, stageA...); err == nil {
		t.Fatal("another service bypassed lock")
	}
	if err := request(s, nil, stageA...); err != nil {
		t.Fatal("idempotent stage retry:", err)
	}
	if err := request(s, []byte("yes"), "fs", "write", "file", "--offset", "0", "--size", "3", "--sha256", digest([]byte("yes")), "--transfer-id", "A"); err != nil {
		t.Fatal(err)
	}
	if err := request(s, nil, "fs", "commit", "file", "--sha256", digest([]byte("yes")), "--transfer-id", "A"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "file")); err != nil || string(data) != "yes" {
		t.Fatalf("bad committed file: %q %v", data, err)
	}
	if err := request(other, []byte("new"), "put", "file"); err != nil {
		t.Fatal("commit did not release OS lock:", err)
	}
	if err := request(s, nil, stageA...); err != nil {
		t.Fatal(err)
	}
	if err := request(s, nil, "fs", "abort", "file", "--transfer-id", "A"); err != nil {
		t.Fatal(err)
	}
	if err := request(other, nil, stageA...); err != nil {
		t.Fatal("abort did not release OS lock:", err)
	}
}

func TestTransferExpiryAndCloseReleaseReservation(t *testing.T) {
	root := t.TempDir()
	s := New(root)
	defer s.Close()
	path := filepath.Join(root, "target")
	release, err := s.reserveWrite(path, "A", "stage")
	if err != nil {
		t.Fatal(err)
	}
	release(true)
	key, _ := canonicalPath(path)
	s.writes.Lock()
	s.writes.leases[key].expires = time.Now().Add(-time.Second)
	s.writes.Unlock()
	s.expireLease(key, "A")
	release, err = s.reserveWrite(path, "B", "stage")
	if err != nil {
		t.Fatal("expired reservation retained:", err)
	}
	release(true)
	s.Close()
	other := New(root)
	defer other.Close()
	release, err = other.reserveWrite(path, "C", "stage")
	if err != nil {
		t.Fatal("closed reservation retained:", err)
	}
	release(true)
}
