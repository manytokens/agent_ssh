package execsvc

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
)

type Size struct{ Cols, Rows uint16 }
type terminal interface {
	io.ReadWriteCloser
	Resize(Size) error
	Wait() (int, error)
	Kill()
}

// Terminal is a process with a real terminal, including window resizing.
type Terminal = terminal

// StartTerminal starts cmd with a PTY/ConPTY rather than redirected stdio.
func StartTerminal(cmd *exec.Cmd, size Size) (Terminal, error) {
	return startTerminal(cmd, size)
}

// HandlePTY runs a real terminal. Its output merges stderr into stdout, as real
// terminals do. Window changes apply to the same PTY rather than a new shell.
func (s *Service) HandlePTY(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer, size Size, resize <-chan Size) error {
	if len(args) == 0 {
		return errors.New("PTY command required")
	}
	o, e := parse(args[1:])
	if e != nil {
		return e
	}
	if o.json {
		return errors.New("--json requires non-PTY execution because terminal output merges stdout and stderr")
	}
	var cmd *exec.Cmd
	cleanup := func() {}
	if args[0] == "bash" || args[0] == "wsl" || ((args[0] == "run" || args[0] == "exec") && len(o.argv) > 0) {
		cmd, cleanup, e = s.command(args[0], o)
	} else {
		sh := o.shell
		if sh == "" {
			sh = s.shell
		}
		var p string
		p, e = resolveShell(sh)
		if e == nil {
			a := o.argv
			if len(a) == 0 && powerShell(p) {
				a = []string{"-NoLogo"}
			} else if len(a) == 0 {
				a = []string{"--noprofile", "--norc", "-i"}
			}
			cmd = exec.Command(p, a...)
			cmd.Dir = o.cwd
			if cmd.Dir == "" {
				cmd.Dir = s.workdir
			}
		}
	}
	if e != nil {
		return e
	}
	defer cleanup()
	if o.dry {
		plan := dryPlan(args[0], cmd, o)
		plan["pty"] = true
		if args[0] != "run" && args[0] != "exec" {
			delete(plan, "script")
		}
		return jsonOut(out, plan)
	}
	if size.Cols == 0 {
		size.Cols = 120
	}
	if size.Rows == 0 {
		size.Rows = 30
	}
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}
	p, e := startTerminal(cmd, size)
	if e != nil {
		return e
	}
	defer p.Close()
	var once sync.Once
	kill := func() { once.Do(p.Kill) }
	defer kill()
	copied := make(chan struct{})
	go func() { io.Copy(out, p); close(copied) }()
	go func() {
		if in != nil {
			io.Copy(p, in)
		}
	}()
	done := make(chan struct{})
	n := 0
	var waitErr error
	go func() { n, waitErr = p.Wait(); close(done) }()
	for {
		select {
		case <-done:
			<-copied
			if waitErr != nil {
				return waitErr
			}
			return exit(n)
		case <-ctx.Done():
			kill()
			<-done
			<-copied
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return exit(124)
			}
			return ctx.Err()
		case <-s.ctx.Done():
			kill()
			<-done
			<-copied
			return s.ctx.Err()
		case z, ok := <-resize:
			if !ok {
				resize = nil
				continue
			}
			if e := p.Resize(z); e != nil {
				kill()
				<-done
				<-copied
				return e
			}
		}
	}
}
