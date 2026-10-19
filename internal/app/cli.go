package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agent_ssh/internal/localssh"
	"agent_ssh/internal/platform"
	"agent_ssh/internal/state"
	"agent_ssh/internal/tunnel"
	"agent_ssh/internal/version"
	"golang.org/x/crypto/ssh"
)

var consoleOutput = platform.ConsoleWriter(os.Stdout)

const help = `agent_ssh / assh v` + version.Version + `

Usage (SSH-ARGS: a destination plus any ssh options, in any order):
  assh init [--state-dir DIR]
  assh authorize [--state-dir DIR] [agent-key.pub]
  assh login SSH-ARGS                    Plain ssh, e.g. to accept the host key
  assh start [OPTIONS] SSH-ARGS          Start a background reverse tunnel
  assh run [OPTIONS] SSH-ARGS            Run in foreground; Ctrl+C stops it
  assh [connect] [OPTIONS] SSH-ARGS      SSH shell with a session-owned tunnel
  assh status [--state-dir DIR] [--json]
  assh stop [--state-dir DIR]
  assh exec [--timeout 30s] [--json] [--dry-run] 'SCRIPT'
  assh info|ps|ports|capabilities --json
  assh fs ls|stat|hash|find PATH --json
  assh session|job ...                  Uses the running local service
  assh mcp                             MCP stdio, no stdout banner
  assh dry-run OPERATION ...            Plan without executing

assh options (long names; everything else is for OpenSSH):
  --state-dir DIR      Device identity and runtime directory (one relay per profile)
  --remote-port PORT  Relay loopback port (default 0: auto, tries 22222 onward)
  --workdir DIR       Local shell/SFTP starting directory (default current directory)
  --shell PATH        Default: pwsh/powershell on Windows, bash on Linux and macOS
  --ssh PATH          Native OpenSSH executable (default ssh)
  --no-shell          With connect: detach a persistent tunnel, like start
  --connect-timeout N SSH connect timeout in seconds (default 10)
  --allow-clipboard   Enable text clipboard tools (default off)
  --no-audit          Do not record operations in state-dir/audit.jsonl
  --events-file PATH JSONL connection events (default state-dir/events.jsonl)
  --event-webhook URL Optional HTTP(S) connection event delivery

Every other argument goes to OpenSSH unchanged (-J, -L/-R/-D, -A, -v, -p,
-i, -F, -o ...) and OpenSSH reports any error in it. The interactive login
gets all of them; the background tunnel gets the connection options only,
plus the port forwards when there is no login (start, run, --no-shell).
With -A the relay shell has your own agent; the assh helpers keep using the
tunnel's agent, which they look up on each call.

The relay must allow TCP and agent forwarding and run a POSIX login shell;
the interactive environment also needs bash, base64 and gzip there.
Background authentication uses BatchMode and strict known-host verification.
Use 'assh login' first to verify the host and configure key/ssh-agent login.
Agent sessions run as the current OS user; SSH usernames do not switch accounts.
Reverse access uses a dedicated memory-only forwarded agent; no relay config files.
authorize optionally adds extra agent keys; without a file it imports ~/.ssh/authorized_keys.
In the relay shell use assh help for all agent tools; run there executes a
command. Local assh run keeps its original meaning: foreground tunnel service.
`

func Main(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(consoleOutput, help)
		return nil
	}
	verb := args[0]
	if isToolVerb(verb) {
		return toolMain(args)
	}
	switch verb {
	case "help", "--help", "-h":
		fmt.Fprint(consoleOutput, help)
		return nil
	case "version", "--version":
		fmt.Fprintln(consoleOutput, "assh v"+version.Version)
		return nil
	case "init", "authorize", "login", "run", "start", "connect", "status", "stop":
		args = args[1:]
	default:
		verb = "connect"
	}
	defaults, err := state.DefaultDir()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(platform.ConsoleWriter(os.Stderr))
	dir := fs.String("state-dir", defaults, "device state directory")
	jsonOutput := fs.Bool("json", false, "print JSON")
	workdir := fs.String("workdir", "", "shell and SFTP starting directory")
	shell := fs.String("shell", "", "shell executable")
	sshPath := fs.String("ssh", "ssh", "OpenSSH executable")
	remotePort := fs.Int("remote-port", 0, "relay loopback port (0: automatic)")
	timeout := fs.Int("connect-timeout", 10, "connect timeout in seconds")
	noShell := fs.Bool("no-shell", false, "do not open an interactive shell")
	allowClipboard := fs.Bool("allow-clipboard", false, "allow text clipboard tools")
	noAudit := fs.Bool("no-audit", false, "do not write state-dir/audit.jsonl")
	eventsFile := fs.String("events-file", "", "JSONL connection events (default state-dir/events.jsonl)")
	eventWebhook := fs.String("event-webhook", "", "optional HTTP(S) event webhook")
	args, positionals, err := splitArgs(fs, args)
	if err != nil {
		return err
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	*dir, err = absolutePath(*dir)
	if err != nil {
		return err
	}
	switch verb {
	case "init":
		if len(positionals) != 0 {
			return errors.New("init does not take a destination")
		}
		lock, err := acquire(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err := state.Init(*dir); err != nil {
			return err
		}
		signer, err := state.HostSigner(*dir)
		if err != nil {
			return err
		}
		fmt.Fprintf(consoleOutput, "State: %s\nDevice: %s\nHost key: %s", *dir, ssh.FingerprintSHA256(signer.PublicKey()), ssh.MarshalAuthorizedKey(signer.PublicKey()))
		fmt.Fprintln(consoleOutput, "Ready. Run assh user@relay; reverse access uses a memory-only agent.")
		return nil
	case "authorize":
		if len(positionals) > 1 {
			return errors.New("usage: assh authorize [--state-dir DIR] [agent-key.pub]")
		}
		var source string
		var data []byte
		if len(positionals) == 0 {
			source, err = state.OpenSSHAuthorizedKeysPath()
			if err != nil {
				return err
			}
			data, err = state.ReadOpenSSHAuthorizedKeys(source)
		} else {
			source, err = absolutePath(positionals[0])
			if err != nil {
				return err
			}
			data, err = os.ReadFile(source)
		}
		if err != nil {
			return err
		}
		keys, err := state.ParseKeys(data)
		if err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		lock, err := acquire(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err := state.Init(*dir); err != nil {
			return err
		}
		path := filepath.Join(*dir, "authorized_keys")
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if len(existing) > 0 && existing[len(existing)-1] != '\n' {
			if _, err := f.WriteString("\n"); err != nil {
				return err
			}
		}
		for _, key := range keys {
			line := ssh.MarshalAuthorizedKey(key)
			if strings.Contains(string(existing), strings.TrimSpace(string(line))) {
				continue
			}
			if _, err := f.Write(line); err != nil {
				return err
			}
		}
		fmt.Fprintf(consoleOutput, "Authorized %d agent key(s) from %s.\n", len(keys), source)
		return nil
	case "status":
		if len(positionals) != 0 {
			return errors.New("status does not take a destination")
		}
		s, err := getStatus(*dir)
		if err != nil {
			s = Status{Phase: "stopped"}
		}
		if *jsonOutput {
			return printJSON(s)
		}
		showStatus(s)
		return nil
	case "stop":
		if len(positionals) != 0 {
			return errors.New("stop does not take a destination")
		}
		if _, err := controlRequest(*dir, http.MethodPost, "/stop"); err != nil {
			return fmt.Errorf("cannot stop profile: %w", err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := getStatus(*dir); err != nil {
				// The listener may close slightly before the OS lock is released.
				if f, err := acquire(*dir); err == nil {
					f.Close()
					fmt.Fprintln(consoleOutput, "Stopped.")
					return nil
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return errors.New("stop requested, but shutdown has not completed")
	}
	if len(positionals) == 0 {
		return errors.New("specify a user@relay destination and any OpenSSH options")
	}
	if *remotePort < 0 || *remotePort > 65535 || *timeout < 1 || *timeout > 300 {
		return errors.New("invalid remote port or connect timeout")
	}
	*sshPath, err = exec.LookPath(*sshPath)
	if err != nil {
		return fmt.Errorf("native OpenSSH client not found: %w", err)
	}
	*sshPath, err = filepath.Abs(*sshPath)
	if err != nil {
		return err
	}
	if verb == "login" {
		return plainLogin(*sshPath, positionals)
	}
	destination, effective, err := describeDestination(*sshPath, positionals)
	if err != nil {
		return err
	}
	// Without an interactive login, the tunnel is the only connection and
	// carries the user's port forwards.
	forwards := verb != "connect" || *noShell
	tc := tunnel.Config{SSH: *sshPath, Destination: destination, SSHArgs: positionals, Effective: effective, RemotePort: *remotePort, ConnectTimeout: *timeout, Forwards: forwards}
	*shell, err = localssh.ResolveShell(*shell)
	if err != nil {
		return err
	}
	if *workdir == "" {
		*workdir, err = os.Getwd()
	} else {
		*workdir, err = absolutePath(*workdir)
	}
	if err != nil {
		return err
	}
	info, err := os.Stat(*workdir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("workdir is not a directory")
	}
	if *eventsFile != "" {
		*eventsFile, err = absolutePath(*eventsFile)
		if err != nil {
			return err
		}
	}
	if err := validateWebhook(*eventWebhook); err != nil {
		return err
	}
	opts := Options{StateDir: *dir, Shell: *shell, WorkDir: *workdir, Tunnel: tc, AllowClipboard: *allowClipboard, NoAudit: *noAudit, EventsFile: *eventsFile, EventWebhook: *eventWebhook}
	if verb == "run" {
		return run(opts)
	}
	if verb == "connect" && !*noShell {
		return connect(opts)
	}
	return start(opts)
}

func printJSON(value any) error {
	e := json.NewEncoder(consoleOutput)
	e.SetIndent("", "  ")
	return e.Encode(value)
}

func absolutePath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if len(path) == 1 {
			path = home
		} else {
			path = filepath.Join(home, path[2:])
		}
	}
	return filepath.Abs(path)
}

func showStatus(s Status) {
	fmt.Fprintf(consoleOutput, "%s", s.Phase)
	if s.Destination != "" {
		// ASCII only: a console on a legacy code page (e.g. 936) garbles dashes and arrows.
		fmt.Fprintf(consoleOutput, " - %s -> %s", s.Destination, s.RemoteAddress)
	}
	fmt.Fprintln(consoleOutput)
	if s.DeviceID != "" {
		fmt.Fprintln(consoleOutput, "Device:", s.DeviceID)
	}
	if s.RelayCommand != "" {
		fmt.Fprintln(consoleOutput, "In the assh SSH session: assh 'Get-Location'")
		fmt.Fprintln(consoleOutput, "Other relay sessions:", s.RelayCommand)
	}
	if s.LastError != "" {
		fmt.Fprintln(consoleOutput, "Last error:", s.LastError)
	}
}

// plainLogin is ssh with the given arguments, for verifying the relay's host
// key and setting up key or agent login before the first assh connection.
func plainLogin(sshPath string, args []string) error {
	cmd := exec.Command(sshPath, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	stop, err := platform.StartInteractive(cmd)
	if err != nil {
		return err
	}
	defer stop()
	return cmd.Wait()
}

// describeDestination asks OpenSSH to evaluate the arguments (ssh -G), so
// mistakes surface as OpenSSH's own error before any connection starts, and
// returns user@host[:port] for status output with a digest of the effective
// configuration. assh's sessions run their own RemoteCommand; a placeholder
// lets OpenSSH reject a command-line command.
func describeDestination(sshPath string, args []string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshPath, append([]string{"-G", "-o", "RemoteCommand=:"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return "", "", fmt.Errorf("ssh: %s", message)
		}
		return "", "", fmt.Errorf("ssh -G: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(stdout.Bytes()))
	values := map[string]string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		if _, seen := values[key]; !seen {
			values[key] = value
		}
	}
	if values["hostname"] == "" {
		return strings.Join(args, " "), digest, nil
	}
	destination := values["hostname"]
	if values["user"] != "" {
		destination = values["user"] + "@" + destination
	}
	if port := values["port"]; port != "" && port != "22" {
		destination += ":" + port
	}
	return destination, digest, nil
}

// loginContext runs native ssh directly on this terminal, exactly as a plain
// ssh login would: no pseudo console in between and no filtered output. The
// assh environment arrives with the session command (see LoginArgs).
func loginContext(ctx context.Context, c tunnel.Config) error {
	cmd := exec.CommandContext(ctx, c.SSH, c.LoginArgs()...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	stop, err := platform.StartInteractive(cmd)
	if err != nil {
		return err
	}
	defer stop()
	return cmd.Wait()
}

func start(opts Options) error {
	if current, err := getStatus(opts.StateDir); err == nil {
		if current.ConfigurationID != configurationID(opts) {
			return errors.New("profile already runs with different settings; stop it first or use another --state-dir")
		}
		showStatus(current)
		if current.Phase != "online" {
			return errors.New("background tunnel is reconnecting; inspect status or assh.log")
		}
		return nil
	}
	// Initialize the persistent device identity before detaching. The child
	// creates its temporary reverse-access identity only in memory.
	lock, err := acquire(opts.StateDir)
	if err != nil {
		return err
	}
	if err = state.Init(opts.StateDir); err != nil {
		lock.Close()
		return err
	}
	lock.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"run", "--state-dir", opts.StateDir, "--workdir", opts.WorkDir, "--shell", opts.Shell, "--ssh", opts.Tunnel.SSH,
		"--remote-port", fmt.Sprint(opts.Tunnel.RemotePort), "--connect-timeout", fmt.Sprint(opts.Tunnel.ConnectTimeout)}
	if opts.AllowClipboard {
		args = append(args, "--allow-clipboard")
	}
	if opts.NoAudit {
		args = append(args, "--no-audit")
	}
	if opts.EventsFile != "" {
		args = append(args, "--events-file", opts.EventsFile)
	}
	if opts.EventWebhook != "" {
		args = append(args, "--event-webhook", opts.EventWebhook)
	}
	// The OpenSSH arguments follow assh's own unchanged; the child reads
	// them back the same way.
	args = append(args, opts.Tunnel.SSHArgs...)
	logPath := filepath.Join(opts.StateDir, "assh.log")
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = log, log
	platform.Detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap on Unix while this parent lives; releasing a process is sufficient
	// on Windows and after the parent exits (the OS adopts the background child).
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(time.Duration(opts.Tunnel.ConnectTimeout+15) * time.Second)
	for time.Now().Before(deadline) {
		if s, err := getStatus(opts.StateDir); err == nil && s.Phase == "online" {
			if s.ConfigurationID != configurationID(opts) {
				return errors.New("profile was concurrently started with different settings; stop it first or choose another --state-dir")
			}
			showStatus(s)
			return nil
		}
		select {
		case err := <-exited:
			return fmt.Errorf("background process exited (%v); inspect %s", err, logPath)
		case <-time.After(150 * time.Millisecond):
		}
	}
	if s, err := getStatus(opts.StateDir); err == nil && s.LastError != "" {
		return fmt.Errorf("background process started but tunnel is not online: %s (it keeps retrying; stop it with 'assh stop --state-dir %q')", s.LastError, opts.StateDir)
	}
	return fmt.Errorf("background process started but tunnel is not online; inspect 'assh status --state-dir %q --json' and %s (it keeps retrying)", opts.StateDir, logPath)
}
