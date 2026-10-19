package filesvc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"agent_ssh/internal/platform"
)

// Resolve existing ancestors as well as the final component, so aliases into
// a not-yet-created destination cannot bypass overlap checks or write locks.
func canonicalPath(path string) (string, error) {
	p, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(p)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			if runtime.GOOS == "windows" {
				resolved = strings.ToLower(resolved)
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", err
		}
		suffix = append(suffix, filepath.Base(p))
		p = parent
	}
}

func inside(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func overlaps(a, b string) bool {
	// Staging paths are reserved along with their final filename.
	a, b = strings.TrimSuffix(a, ".part"), strings.TrimSuffix(b, ".part")
	return inside(a, b) || inside(b, a)
}

type transferLease struct {
	id      string
	lock    *os.File
	timer   *time.Timer
	expires time.Time
}

type writeLocks struct {
	sync.Mutex
	active map[string]bool
	leases map[string]*transferLease
	closed bool
}

const transferIdleTimeout = 5 * time.Minute

// Directory operations additionally lock each actual file they write. This
// shares the same lock namespace with single-file uploads in other profiles.
func destinationLock(path string) (*os.File, error) {
	path, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}
	lockDir := filepath.Join(os.TempDir(), "assh-transfer-locks")
	if err := os.MkdirAll(lockDir, 0700); err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(strings.TrimSuffix(path, ".part")))
	lock, err := platform.Lock(filepath.Join(lockDir, fmt.Sprintf("%x.lock", digest)))
	if err != nil {
		return nil, fmt.Errorf("destination is busy with another transfer: %w", err)
	}
	return lock, nil
}

func (s *Service) releaseLease(path string) {
	if lease := s.writes.leases[path]; lease != nil {
		lease.timer.Stop()
		lease.lock.Close()
		delete(s.writes.leases, path)
	}
}

func (s *Service) expireLease(path, id string) {
	s.writes.Lock()
	defer s.writes.Unlock()
	if lease := s.writes.leases[path]; lease != nil && lease.id == id {
		if remaining := time.Until(lease.expires); remaining > 0 {
			lease.timer.Reset(remaining)
			return
		}
		if s.writes.active[path] {
			lease.timer.Reset(transferIdleTimeout)
			return
		}
		s.releaseLease(path)
	}
}

func (s *Service) Close() error {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.writes.closed = true
	for path := range s.writes.leases {
		if !s.writes.active[path] {
			s.releaseLease(path)
		}
	}
	return nil
}

// reserveWrite holds direct writes for their duration and tokenized uploads
// across stage/write/commit RPCs. Conflicts fail without modifying .part.
func (s *Service) reserveWrite(path, id, operation string) (func(bool), error) {
	path, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}
	s.writes.Lock()
	defer s.writes.Unlock()
	if s.writes.closed {
		return nil, errors.New("file service closed")
	}
	if s.writes.active == nil {
		s.writes.active = make(map[string]bool)
		s.writes.leases = make(map[string]*transferLease)
	}
	for other := range s.writes.active {
		if overlaps(path, other) {
			return nil, errors.New("destination is busy with another file operation")
		}
	}
	for other, lease := range s.writes.leases {
		if overlaps(path, other) && !(path == other && id != "" && id == lease.id) {
			return nil, errors.New("destination is reserved by another transfer; retry after it finishes")
		}
	}
	lease := s.writes.leases[path]
	if id != "" && lease == nil && operation != "stage" && operation != "abort" {
		return nil, errors.New("transfer expired or was not staged; restart the upload")
	}
	var lock *os.File
	if lease == nil {
		if operation == "abort" {
			return func(bool) {}, nil
		}
		lock, err = destinationLock(path)
		if err != nil {
			return nil, err
		}
		if id != "" {
			lease = &transferLease{id: id, lock: lock, expires: time.Now().Add(transferIdleTimeout)}
			lease.timer = time.AfterFunc(transferIdleTimeout, func() { s.expireLease(path, id) })
			s.writes.leases[path] = lease
		}
	}
	if lease != nil {
		lease.expires = time.Now().Add(transferIdleTimeout)
		lease.timer.Reset(transferIdleTimeout)
	}
	s.writes.active[path] = true
	return func(success bool) {
		s.writes.Lock()
		defer s.writes.Unlock()
		delete(s.writes.active, path)
		if lease == nil {
			lock.Close()
		} else if s.writes.closed || (operation == "commit" && success) || operation == "abort" || (operation == "stage" && !success) {
			s.releaseLease(path)
		}
	}, nil
}
