//go:build !windows

package toolrpc

import (
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func prepareMCPFile(f *os.File) (*os.File, func(), error) {
	fd := int(f.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return nil, nil, err
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		unix.Close(dup)
		return nil, nil, err
	}
	// NewFile sees O_NONBLOCK and registers pipes/terminals with the runtime
	// poller, so Close wakes a pending Read or Write. Keep the caller's file
	// alive and restore its shared descriptor flags after transport shutdown.
	prepared := os.NewFile(uintptr(dup), f.Name())
	return prepared, func() {
		_ = prepared.Close()
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags)
		runtime.KeepAlive(f)
	}, nil
}
