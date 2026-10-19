package filesvc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Move the named part into a private snapshot before verifying it. Verification
// and publication then use this snapshot, so a replacement of the public .part
// name after verification cannot publish an unverified symlink or other file.
func commitSafePart(target, expected string) (actual string, err error) {
	part := target + ".part"
	f, err := openSafePart(part, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".assh-commit-*")
	if err != nil {
		return "", err
	}
	snapshot := tmp.Name()
	if err = tmp.Close(); err != nil {
		os.Remove(snapshot)
		return "", err
	}
	if err = os.Rename(part, snapshot); err != nil {
		os.Remove(snapshot)
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			if restoreErr := os.Rename(snapshot, part); restoreErr != nil {
				err = fmt.Errorf("%w; restoring staged file failed (retained at %s): %v", err, snapshot, restoreErr)
			}
		}
	}()
	f, err = openSafePart(snapshot, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	actual = hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return "", errors.New("file SHA256 mismatch; .part retained for resume")
	}
	if err = os.Rename(snapshot, target); err != nil {
		return "", err
	}
	committed = true
	return actual, nil
}
