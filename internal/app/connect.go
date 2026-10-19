package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"agent_ssh/internal/platform"
)

// A normal SSH session owns its service in the same process. Only explicit
// start/--no-shell detaches a persistent daemon.
func connect(opts Options) error {
	if err := platform.OwnSession(); err != nil {
		return fmt.Errorf("own SSH session processes: %w", err)
	}
	if err := os.MkdirAll(opts.StateDir, 0700); err != nil {
		return err
	}
	logPath := filepath.Join(opts.StateDir, "assh.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	done := make(chan struct{})
	var serviceErr error
	go func() {
		serviceErr = runContext(ctx, opts, log)
		close(done)
	}()
	defer func() { cancel(); <-done }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(time.Duration(opts.Tunnel.ConnectTimeout+15) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-done:
			return serviceErr
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			if s, err := getStatus(opts.StateDir); err == nil && s.LastError != "" {
				return fmt.Errorf("tunnel did not become ready: %s (see %s)", s.LastError, logPath)
			}
			return fmt.Errorf("tunnel did not become ready; inspect %s", logPath)
		case <-ticker.C:
			s, err := getStatus(opts.StateDir)
			if err != nil || s.PID != os.Getpid() || s.Phase != "online" {
				continue
			}
			showStatus(s)
			c := opts.Tunnel
			c.ForwardAgent, c.HostKey = s.AgentEndpoint, s.HostKey
			c.RemotePort, c.AgentSocket = s.RemotePort, s.AgentSocket
			// An explicit stop also ends the interactive login.
			loginCtx, stopLogin := context.WithCancel(ctx)
			defer stopLogin()
			go func() {
				select {
				case <-done:
					stopLogin()
				case <-loginCtx.Done():
				}
			}()
			return loginContext(loginCtx, c)
		}
	}
}
