//go:build !windows

package platform

import (
	"io"
	"os"
	"os/exec"
	"syscall"
)

func ConsoleWriter(f *os.File) io.Writer { return f }

func OwnSession() error { return nil }

func Lock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func Detach(cmd *exec.Cmd)  { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func Prepare(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// Tracked and KillRecorded only matter on Windows, where a packaged shell's
// children can escape the job object. Unix process groups are killed whole.
func Tracked() []Record           { return nil }
func KillRecorded(_ []Record) int { return 0 }

// Start creates an independently cancellable process group.
func Start(cmd *exec.Cmd) (func(), error) {
	Prepare(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }, nil
}

func StartInteractive(cmd *exec.Cmd) (func(), error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { _ = cmd.Process.Kill() }, nil
}
