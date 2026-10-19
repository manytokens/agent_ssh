//go:build !windows

package execsvc

import (
	"github.com/creack/pty"
	"os"
	"os/exec"
	"syscall"
)

type unixTerminal struct {
	*os.File
	cmd *exec.Cmd
}

func startTerminal(cmd *exec.Cmd, size Size) (terminal, error) {
	f, e := pty.StartWithSize(cmd, &pty.Winsize{Cols: size.Cols, Rows: size.Rows})
	if e != nil {
		return nil, e
	}
	return &unixTerminal{f, cmd}, nil
}
func (t *unixTerminal) Resize(z Size) error {
	return pty.Setsize(t.File, &pty.Winsize{Cols: z.Cols, Rows: z.Rows})
}
func (t *unixTerminal) Wait() (int, error) { e := t.cmd.Wait(); return code(e), nil }
func (t *unixTerminal) Kill()              { syscall.Kill(-t.cmd.Process.Pid, syscall.SIGKILL) }
