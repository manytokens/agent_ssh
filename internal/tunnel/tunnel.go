// Package tunnel delegates transport and authentication to native OpenSSH.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os/exec"
	"strings"
	"sync"
	"time"

	"agent_ssh/internal/platform"
)

const readyMarker = "ASSH_READY_V1"

type Config struct {
	SSH string `json:"ssh"`
	// Destination only describes the relay (from ssh -G); SSHArgs, the user's
	// OpenSSH arguments exactly as given, name it to OpenSSH.
	Destination string   `json:"destination"`
	SSHArgs     []string `json:"ssh_args"`
	// Effective is a digest of the configuration OpenSSH resolves from
	// SSHArgs (ssh -G); the same settings in another order match.
	Effective      string `json:"effective,omitempty"`
	RemotePort     int    `json:"remote_port"`
	LocalAddress   string `json:"local_address"`
	ConnectTimeout int    `json:"connect_timeout"`
	// Forwards gives the user's port forwards to the tunnel, for a profile
	// without an interactive login (start, run, --no-shell).
	Forwards     bool   `json:"forwards,omitempty"`
	ForwardAgent string `json:"-"`
	HostKey      string `json:"-"`
	// AgentSocket is the tunnel's forwarded agent on the relay when the login
	// starts; relay helpers fall back to it when they cannot look it up.
	AgentSocket string `json:"-"`
}

// OpenSSH's single-letter options (ssh.c getopt string) that take a value.
const sshValueFlags = "bceilmopBDEFIJLOPQRSwW"

// Options that belong to an interactive session rather than to the
// connection: forwarding, terminal, mode and logging destinations. The
// tunnel and health probe leave them to the login, which receives them all.
const sshSessionFlags = "aADEefGLMnNOqQRsStTVwWxXyY"

var sshSessionOptions = map[string]bool{
	"clearallforwardings": true, "controlmaster": true, "controlpath": true, "controlpersist": true,
	"dynamicforward": true, "escapechar": true, "forkafterauthentication": true, "forwardagent": true,
	"forwardx11": true, "forwardx11trusted": true, "localcommand": true, "localforward": true,
	"loglevel": true, "permitlocalcommand": true, "remotecommand": true, "remoteforward": true,
	"requesttty": true, "sessiontype": true, "stdinnull": true, "tunnel": true, "tunneldevice": true,
}

// ConnectionArgs is SSHArgs without session options, for the background
// tunnel and health probe: separate connections which must not bind the
// login's forwards (unless Forwards is set), take a terminal or detach.
// Everything else, including options this list does not know, reaches
// OpenSSH unchanged. Like ssh, it reads options before and after the
// destination; the first argument after the destination starts the remote
// command, which is kept for OpenSSH to reject (assh supplies RemoteCommand).
func (c Config) ConnectionArgs() []string {
	args, _ := c.connectionArgs()
	return args
}

// connectionArgs also reports whether options may still follow the result,
// that is, whether it ends without "--" or a remote command.
func (c Config) connectionArgs() ([]string, bool) {
	var args []string
	positional := 0
	for i := 0; i < len(c.SSHArgs); i++ {
		arg := c.SSHArgs[i]
		if arg == "--" || positional > 0 && !strings.HasPrefix(arg, "-") {
			return append(args, c.SSHArgs[i:]...), false
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional++
			args = append(args, arg)
			continue
		}
		for j := 1; j < len(arg); j++ {
			flag := arg[j]
			if !strings.ContainsRune(sshValueFlags, rune(flag)) {
				if !c.session(flag, "") {
					args = append(args, "-"+string(flag))
				}
				continue
			}
			value := arg[j+1:]
			if value == "" && i+1 < len(c.SSHArgs) {
				i++
				value = c.SSHArgs[i]
			}
			if !c.session(flag, value) {
				args = append(args, "-"+string(flag), value)
			}
			break
		}
	}
	return args, true
}

// session reports whether an option (with its value) belongs to the login.
func (c Config) session(flag byte, value string) bool {
	if c.Forwards && strings.ContainsRune("DLR", rune(flag)) {
		return false
	}
	if flag != 'o' {
		return strings.ContainsRune(sshSessionFlags, rune(flag))
	}
	name := optionName(value)
	if c.Forwards && (name == "localforward" || name == "remoteforward" || name == "dynamicforward") {
		return false
	}
	return sshSessionOptions[name]
}

// optionName is the lower-case keyword of an -o value (Key=Value or Key Value).
func optionName(option string) string {
	option = strings.TrimSpace(option)
	if i := strings.IndexAny(option, "= \t"); i >= 0 {
		option = option[:i]
	}
	return strings.ToLower(option)
}

// remoteCommand passes a session command as RemoteCommand, so OpenSSH itself
// rejects a second command given on the command line; '%' would start a token.
func remoteCommand(command string) []string {
	return []string{"-o", "RemoteCommand=" + strings.ReplaceAll(command, "%", "%%")}
}

func (c Config) Args() []string {
	// OpenSSH takes the first value for each option. Connection-owned lifecycle
	// settings precede user options; user options precede heartbeat defaults.
	args := []string{"-T",
		"-o", "ForwardAgent=" + c.ForwardAgent,
		"-o", "BatchMode=yes",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ControlMaster=no", "-o", "ControlPath=none",
		"-o", "ForkAfterAuthentication=no", "-o", "StdinNull=no",
		"-o", "SessionType=default",
		"-o", "StrictHostKeyChecking=yes",
		"-R", fmt.Sprintf("127.0.0.1:%d:%s", c.RemotePort, c.LocalAddress)}
	// A POSIX relay account is required. OpenSSH waits for initial forwarding
	// confirmations before requesting this session. cat keeps the session
	// alive without polling or a custom relay service.
	args = append(args, remoteCommand(c.ReadyCommand())...)
	defaults := []string{
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
		"-o", fmt.Sprintf("ConnectTimeout=%d", c.ConnectTimeout)}
	user, open := c.connectionArgs()
	if !open {
		return append(append(args, defaults...), user...)
	}
	return append(append(args, user...), defaults...)
}

type Update struct {
	Phase       string
	Attempt     int
	Error       string
	AgentSocket string
	RemotePort  int
}

type tail struct {
	mu   sync.Mutex
	data string
	out  io.Writer
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data += string(p)
	if len(t.data) > 4096 {
		t.data = t.data[len(t.data)-4096:]
	}
	_, _ = t.out.Write(p)
	return len(p), nil
}
func (t *tail) String() string { t.mu.Lock(); defer t.mu.Unlock(); return strings.TrimSpace(t.data) }

func Run(ctx context.Context, c Config, logger *slog.Logger, diagnostics io.Writer, update func(Update)) error {
	attempt := 0
	delay := time.Second
	automatic := c.RemotePort == 0
	if automatic {
		c.RemotePort = 22222
	}
	for ctx.Err() == nil {
		attempt++
		update(Update{Phase: "connecting", Attempt: attempt, RemotePort: c.RemotePort})
		started := time.Now()
		err := once(ctx, c, diagnostics, func(socket string) {
			// Keep the chosen port across reconnects so exported shell env stays valid.
			automatic = false
			update(Update{Phase: "online", Attempt: attempt, AgentSocket: socket, RemotePort: c.RemotePort})
			logger.Info("reverse tunnel online", "relay", c.Destination, "port", c.RemotePort)
		})
		if ctx.Err() != nil {
			return nil
		}
		if automatic && forwardingFailed(err, c.RemotePort) {
			if c.RemotePort >= 22285 {
				return fmt.Errorf("automatic relay ports 22222-22285 unavailable: %w", err)
			}
			logger.Info("relay port unavailable; trying next", "port", c.RemotePort)
			c.RemotePort++
			continue
		}
		msg := "SSH transport exited"
		if err != nil {
			msg = err.Error()
		}
		update(Update{Phase: "reconnecting", Attempt: attempt, Error: msg, RemotePort: c.RemotePort})
		logger.Warn("tunnel disconnected; retrying", "error", msg, "delay", delay)
		if time.Since(started) > time.Minute {
			delay = time.Second
		}
		timer := time.NewTimer(delay + time.Duration(rand.Int64N(int64(delay/4+1))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if delay < 30*time.Second {
			delay *= 2
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
	return nil
}

func forwardingFailed(err error, port int) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), fmt.Sprintf("remote port forwarding failed for listen port %d", port))
}

func once(ctx context.Context, c Config, diagnostics io.Writer, ready func(string)) error {
	cmd := exec.Command(c.SSH, c.Args()...)
	cmd.Env = c.Env()
	stderr := &tail{out: diagnostics}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()
	stop, err := platform.Start(cmd)
	if err != nil {
		return err
	}
	defer func() { stop() }()
	readDone := make(chan struct{})
	readyCh := make(chan string, 1)
	go func() {
		defer close(readDone)
		scanner := bufio.NewScanner(stdout)
		var socket string
		for scanner.Scan() {
			if value, ok := strings.CutPrefix(scanner.Text(), "ASSH_AGENT_SOCKET "); ok {
				socket = value
				continue
			}
			if scanner.Text() == readyMarker {
				select {
				case readyCh <- socket:
				default:
				}
			} else {
				fmt.Fprintln(diagnostics, scanner.Text())
			}
		}
	}()
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	timer := time.NewTimer(time.Duration(c.ConnectTimeout+15) * time.Second)
	defer timer.Stop()
	var result error
	active := true
	for active {
		select {
		case socket := <-readyCh:
			timer.Stop()
			ready(socket)
		case result = <-wait:
			active = false
		case <-ctx.Done():
			stop()
			stop = func() {}
			result = <-wait
			active = false
		case <-timer.C:
			stop()
			stop = func() {}
			<-wait
			result = errors.New("timed out waiting for relay readiness; relay needs a POSIX shell and TCP forwarding")
			active = false
		}
	}
	<-readDone
	if result != nil {
		return fmt.Errorf("%w: %s", result, stderr.String())
	}
	return nil
}
