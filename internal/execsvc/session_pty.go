package execsvc

import (
	"agent_ssh/internal/toolproto"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"
)

func (s *Service) startPTYTask(t *task, o options) (*task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		t.closeDisk()
		return nil, errors.New("execution service closed")
	}
	if o.cols == 0 {
		o.cols = 120
	}
	if o.rows == 0 {
		o.rows = 30
	}
	p, e := startTerminal(t.cmd, Size{o.cols, o.rows})
	if e != nil {
		t.closeDisk()
		return nil, e
	}
	t.terminal = p
	t.input = p
	var once sync.Once
	t.kill = func() { once.Do(p.Kill) }
	s.tasks[t.id] = t
	copied := make(chan struct{})
	go func() {
		var out io.Writer = &t.stdout
		if t.diskOut != nil {
			out = io.MultiWriter(t.diskOut, &t.stdout)
		}
		io.Copy(out, p)
		close(copied)
	}()
	go func() {
		n, _ := p.Wait()
		<-copied
		t.mu.Lock()
		if t.interrupted {
			t.exitCode = 130
		} else if t.timedOut {
			t.exitCode = 124
		} else {
			t.exitCode = n
		}
		t.finished = time.Now()
		t.mu.Unlock()
		t.kill()
		p.Close()
		t.cleanup()
		t.closeDisk()
		_ = s.persist(t, false)
		close(t.done)
	}()
	go func() {
		var timeout <-chan time.Time
		var timer *time.Timer
		if o.timeout > 0 {
			timer = time.NewTimer(o.timeout)
			defer timer.Stop()
			timeout = timer.C
		}
		select {
		case <-t.done:
		case <-s.ctx.Done():
			t.kill()
		case <-timeout:
			t.mu.Lock()
			t.timedOut = true
			t.mu.Unlock()
			t.kill()
		}
	}()
	return t, nil
}

func resizeAttached(ctx context.Context, t *task) {
	term, ok := toolproto.TerminalFromContext(ctx)
	if !ok || t.terminal == nil {
		return
	}
	if term.Cols > 0 && term.Rows > 0 {
		_ = t.terminal.Resize(Size{uint16(term.Cols), uint16(term.Rows)})
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.done:
			return
		case b, ok := <-term.Resizes:
			if !ok {
				return
			}
			if len(b) >= 8 {
				_ = t.terminal.Resize(Size{uint16(binary.BigEndian.Uint32(b)), uint16(binary.BigEndian.Uint32(b[4:]))})
			}
		}
	}
}
