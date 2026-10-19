//go:build !windows

package reverseagent

import (
	"net"
	"os"
	"path/filepath"
)

func listen() (net.Listener, string, func(), error) {
	dir, err := os.MkdirTemp("", "assh-agent-")
	if err != nil {
		return nil, "", nil, err
	}
	path := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		os.Remove(dir)
		return nil, "", nil, err
	}
	return l, path, func() { _ = os.Remove(path); _ = os.Remove(dir) }, nil
}
