// Package tools is the common business layer for SSH, the local CLI and MCP.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"agent_ssh/internal/audit"
	"agent_ssh/internal/execsvc"
	"agent_ssh/internal/filesvc"
	"agent_ssh/internal/sysinfo"
	"agent_ssh/internal/toolrpc"
)

type Config struct {
	Shell, WorkDir, StateDir string
	AllowClipboard           bool
	Connection               func() any
	Audit                    *audit.Log
}
type Service struct {
	cfg    Config
	exec   *execsvc.Service
	files  *filesvc.Service
	system *sysinfo.Service
}

func New(c Config) *Service {
	return &Service{cfg: c, exec: execsvc.New(c.Shell, c.WorkDir, c.StateDir), files: filesvc.New(c.WorkDir), system: &sysinfo.Service{WorkDir: c.WorkDir, Shell: c.Shell, AllowClipboard: c.AllowClipboard}}
}
func (s *Service) Close() error {
	defer s.files.Close()
	return s.exec.Close()
}

const Help = `assh agent tools
The target is the computer running assh, not the Linux relay.
Use assh info --json for the real OS user, shell and working directory.

  assh run [--timeout 30s] [--json] [--dry-run] 'PowerShell script'
  assh bash [-lc 'script']          Git Bash on Windows, native Bash on Linux
  assh wsl [-d DISTRO] [-u USER] [--cd PATH] [--exec COMMAND ARGS...]
  assh fs ls|stat|hash|find PATH --json
  assh put SOURCE DEST             verified, resumable file/directory upload
  assh get SOURCE DEST             verified, resumable file/directory download
  assh sync SOURCE DEST [--exclude PATTERN] [--dry-run]
  assh session new|list|send|read|attach|close ...
  assh job start|list|log|wait|kill|remove ...
  assh job clean [--older-than 24h] [--dry-run]
  assh watch DIRECTORY             JSONL filesystem events
  assh info|ps|ports --json
  assh clip get|set                text clipboard; requires --allow-clipboard
  assh capabilities --json         machine-readable discovery
  assh connection                 connection metadata; relay --write FILE is opt-in
  assh status                     tunnel phase, reconnects, uptime, errors, live sessions/jobs
  assh mcp                        MCP over SSH stdio (no banner on this stream)
  assh dry-run OPERATION ...       preview, without executing the operation

Scripts are not translated between PowerShell and Bash. Windows absolute file
paths accept D:/dir, /D:/dir and /d/dir. Use --text only for text transfers.
PTY output is a combined terminal stream; --json exec separates stdout/stderr.
Jobs/sessions survive individual SSH tool connections, and end when the assh
service stops. Use explicit start/--no-shell for an independent service.
Dry-run reports argv/cwd or file changes; it never executes arbitrary scripts
and cannot predict their side effects. No filesystem root sandbox is enabled.
Relay file helpers require python3; connection configuration stays in memory.
`

func Normalize(args []string) ([]string, error) {
	var opts []string
	for len(args) > 0 {
		a := args[0]
		if a == "dry-run" || a == "--dry-run" || a == "--json" {
			if a == "dry-run" {
				a = "--dry-run"
			}
			opts = append(opts, a)
			args = args[1:]
			continue
		}
		if a == "--timeout" {
			if len(args) < 2 {
				return nil, errors.New("--timeout needs a duration")
			}
			opts = append(opts, args[:2]...)
			args = args[2:]
			continue
		}
		if strings.HasPrefix(a, "--timeout=") {
			opts = append(opts, "--timeout", strings.TrimPrefix(a, "--timeout="))
			args = args[1:]
			continue
		}
		break
	}
	if len(args) == 0 {
		if len(opts) > 0 {
			return nil, errors.New("specify an operation after options")
		}
		return []string{"help"}, nil
	}
	if len(opts) > 0 {
		switch args[0] {
		case "fs", "session", "job":
			if len(args) < 2 {
				return nil, fmt.Errorf("%s requires a subcommand", args[0])
			}
			pos := 2
			if args[0] != "fs" && len(args) > 2 {
				switch args[1] {
				case "send", "read", "attach", "close", "log", "wait", "kill", "remove":
					pos = 3 // Keep the task ID before options and send payload after them.
				}
			}
			return append(append(append([]string{}, args[:pos]...), opts...), args[pos:]...), nil
		case "run", "exec", "bash", "wsl", "put", "get", "sync", "watch", "info", "ps", "ports", "clip", "help", "capabilities", "connection", "status", "mcp", "ping", "shell":
		default:
			return append(append([]string{"run"}, opts...), args...), nil
		}
	}
	return append(append([]string{args[0]}, opts...), args[1:]...), nil
}
func (s *Service) Handle(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) (err error) {
	raw := args
	args, err = Normalize(args)
	// MCP is a transport; its individual operations re-enter Handle and are
	// recorded here with the same connection attribution.
	if err != nil || args[0] != "mcp" {
		finish := audit.Begin(ctx, s.cfg.Audit, raw)
		defer func() { finish(err) }()
	}
	if err != nil {
		return err
	}
	write := func(v any) error { return json.NewEncoder(out).Encode(v) }
	switch args[0] {
	case "help":
		_, err = io.WriteString(out, Help)
		return err
	case "capabilities":
		return write(map[string]any{"protocol_version": 1, "target_os": runtime.GOOS, "identity": sysinfo.Identity(), "cwd": s.cfg.WorkDir, "shell": s.cfg.Shell, "clipboard_enabled": s.cfg.AllowClipboard, "commands": []string{"run", "exec", "bash", "wsl", "fs", "put", "get", "sync", "session", "job", "watch", "info", "ps", "ports", "clip", "connection", "status", "mcp", "dry-run"}, "dry_run": "plans only; arbitrary script effects are not inferred", "file_helper_requires": "python3 on relay", "session_lifetime": "until service stops", "root_restriction": false})
	case "connection":
		if len(args) > 1 && args[1] != "--json" {
			return errors.New("use relay assh connection --write PATH for an optional relay snapshot")
		}
		if s.cfg.Connection != nil {
			return write(s.cfg.Connection())
		}
		return write(map[string]any{"identity": sysinfo.Identity(), "cwd": s.cfg.WorkDir})
	case "ping":
		return write(map[string]any{"pong": true, "time": time.Now().UTC()})
	case "status":
		// Tunnel health as the computer sees it, reachable from the relay.
		result := map[string]any{}
		if s.cfg.Connection != nil {
			if b, e := json.Marshal(s.cfg.Connection()); e == nil {
				_ = json.Unmarshal(b, &result)
			}
		}
		if started, ok := result["started_at"].(string); ok {
			if t, e := time.Parse(time.RFC3339Nano, started); e == nil {
				result["uptime_seconds"] = int(time.Since(t).Seconds())
			}
		}
		if since, ok := result["online_since"].(string); ok {
			if t, e := time.Parse(time.RFC3339Nano, since); e == nil {
				result["online_seconds"] = int(time.Since(t).Seconds())
			}
		}
		sessions, jobs := s.exec.Running()
		result["sessions_running"], result["jobs_running"] = sessions, jobs
		return write(result)
	case "mcp":
		for _, a := range args[1:] {
			if a == "--dry-run" {
				return write(map[string]any{"dry_run": true, "operation": "mcp", "transport": "SSH stdio"})
			}
		}
		return toolrpc.ServeMCP(ctx, in, out, stderr, s.Handle)
	case "shell":
		isDry := false
		for _, a := range args[1:] {
			if a == "--dry-run" {
				isDry = true
			}
		}
		if !isDry {
			id := sysinfo.Identity()
			fmt.Fprintf(out, "assh: %s local shell, OS user %s, cwd %s\r\nUse the relay's assh help / assh capabilities --json for tools.\r\n", runtime.GOOS, id["username"], s.cfg.WorkDir)
		}
		return s.exec.Handle(ctx, args, in, out, stderr)
	case "run", "exec", "bash", "wsl", "session", "job":
		return s.exec.Handle(ctx, args, in, out, stderr)
	case "fs", "put", "get", "sync", "watch":
		return s.files.Handle(ctx, args, in, out, stderr)
	case "info", "ps", "ports", "clip":
		return s.system.Handle(ctx, args, in, out, stderr)
	default:
		return fmt.Errorf("unknown tool %q; use assh help", args[0])
	}
}
