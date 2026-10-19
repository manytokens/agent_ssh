package platform

import (
	"path/filepath"
	"testing"
)

func TestExclusiveLockReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	a, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := Lock(path); err == nil {
		b.Close()
		a.Close()
		t.Fatal("two owners acquired a profile lock")
	}
	a.Close()
	b, err := Lock(path)
	if err != nil {
		t.Fatal("stale lock file prevented restart:", err)
	}
	b.Close()
}
