package app

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"agent_ssh/internal/platform"
	"agent_ssh/internal/telemetry"
	"agent_ssh/internal/toolrpc"
	"agent_ssh/internal/tunnel"
)

func monitorHealth(ctx context.Context, c tunnel.Config, m *telemetry.Metrics, mu *sync.Mutex, status *Status) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := time.Now()
	var read, written uint64
	var nextProbe time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r, w := m.Read.Load(), m.Written.Load()
			elapsed := now.Sub(last).Seconds()
			mu.Lock()
			status.Metrics.Received = r
			status.Metrics.Sent = w
			status.Metrics.ReceiveRate = float64(r-read) / elapsed
			status.Metrics.SendRate = float64(w-written) / elapsed
			snapshot := *status
			mu.Unlock()
			read, written, last = r, w, now
			if snapshot.Phase != "online" || snapshot.AgentSocket == "" || now.Before(nextProbe) {
				continue
			}
			nextProbe = now.Add(30 * time.Second)
			probe, cancel := context.WithTimeout(ctx, 5*time.Second)
			started := time.Now()
			ok := probeRoundTrip(probe, c, snapshot)
			cancel()
			if ok {
				mu.Lock()
				if status.Phase == "online" && status.AgentSocket == snapshot.AgentSocket {
					status.Metrics.RoundTripMS = float64(time.Since(started).Microseconds()) / 1000
					status.Metrics.ProbeAt = time.Now().UTC()
				}
				mu.Unlock()
			}
		}
	}
}

func probeRoundTrip(ctx context.Context, c tunnel.Config, s Status) bool {
	command := tunnel.RelayCommand(s.RemotePort, s.HostKey, s.AgentSocket) + " '" + toolrpc.Encode([]string{"ping"}) + "'"
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
		"-o", "RemoteCommand=" + strings.ReplaceAll(command, "%", "%%"), "-o", "SessionType=default", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=3"}
	args = append(args, c.ConnectionArgs()...)
	cmd := exec.CommandContext(ctx, c.SSH, args...)
	cmd.Env = c.Env()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	stop, err := platform.Start(cmd)
	if err != nil {
		return false
	}
	defer stop()
	err = cmd.Wait()
	return err == nil && strings.Contains(out.String(), `"pong":true`)
}
