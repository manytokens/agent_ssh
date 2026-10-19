//go:build !windows

package filesvc

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Never pass O_TRUNC: validate the opened inode before modifying its data.
func openSafePart(path string, flags int) (*os.File, error) {
	if flags&os.O_TRUNC != 0 {
		return nil, fmt.Errorf("unsafe truncate flag for staged file")
	}
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, &os.PathError{Op: "open staged file", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("staged file must be a regular file with exactly one link: %s", path)
	}
	return f, nil
}
