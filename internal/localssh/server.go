package localssh

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"agent_ssh/internal/audit"
	"agent_ssh/internal/execsvc"
	"agent_ssh/internal/platform"
	"agent_ssh/internal/state"
	"agent_ssh/internal/telemetry"
	"agent_ssh/internal/toolproto"
	"agent_ssh/internal/toolrpc"
	"github.com/jpillora/sshd-lite/sshd"
	"github.com/jpillora/sshd-lite/xssh"
	"golang.org/x/crypto/ssh"
)

func ResolveShell(shell string) (string, error) {
	if shell == "" {
		if runtime.GOOS == "windows" {
			for _, candidate := range []string{"pwsh.exe", "powershell.exe"} {
				if p, err := exec.LookPath(candidate); err == nil {
					return p, nil
				}
			}
			return "", errors.New("PowerShell not found; install PowerShell or set --shell")
		}
		shell = "bash"
	}
	return exec.LookPath(shell)
}

// Start exposes SSH only to local loopback; the OpenSSH process carries it to
// the relay. Both users and commands run as the current OS user.
func Start(ctx context.Context, dir, shell, workdir string, logger *slog.Logger, ephemeral ...ssh.PublicKey) (net.Listener, <-chan error, error) {
	return StartWithTools(ctx, dir, shell, workdir, logger, nil, nil, nil, ephemeral...)
}

// connID names an SSH connection in the audit log by its session ID prefix.
func connID(c ssh.ConnMetadata) string { return hex.EncodeToString(c.SessionID()[:8]) }

// StartWithTools records connections and plain exec commands, and supplies
// connection attribution to the common tool dispatcher for operation auditing.
func StartWithTools(ctx context.Context, dir, shell, workdir string, logger *slog.Logger, handler toolproto.Handler, metrics *telemetry.Metrics, log *audit.Log, ephemeral ...ssh.PublicKey) (net.Listener, <-chan error, error) {
	keys := append([]ssh.PublicKey(nil), ephemeral...)
	if len(keys) == 0 {
		manual, err := state.AgentKeys(dir)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, manual...)
	} else {
		// Only explicit extra keys are additive. Legacy paired remote identities
		// and the user's system agent are not trusted by the new runtime.
		data, err := os.ReadFile(filepath.Join(dir, "authorized_keys"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		if strings.TrimSpace(string(data)) != "" {
			manual, err := state.ParseKeys(data)
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, manual...)
		}
	}
	key, err := os.ReadFile(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		return nil, nil, err
	}
	s, err := sshd.NewServer(sshd.Config{
		Shell: shell, WorkDir: workdir, KeyBytes: key, AuthKeys: keys,
		SFTP: true, TCPForwarding: true, NoClientEnv: true, Logger: logger,
		// SFTP transfers and port forwards are audited at connection level.
		ConnectionHandler: func(connCtx context.Context, c *ssh.ServerConn) {
			opened := time.Now()
			log.Write(audit.Entry{Kind: "connect", Conn: connID(c), User: c.User()})
			<-connCtx.Done()
			log.Write(audit.Entry{Kind: "disconnect", Conn: connID(c), User: c.User(), DurationMS: time.Since(opened).Milliseconds()})
		},
		// Authentication signs through the relay's forwarded agent, so a busy
		// tunnel can push the handshake well past sshd-lite's 10s default. The
		// listener is loopback-only; unauthenticated clients come via the relay.
		HandshakeTimeout: 60 * time.Second,
		Attach: func(serverCtx context.Context, _ net.Addr) (xssh.ExecHandler, io.Closer, error) {
			return func(sess *xssh.Session, text string) (bool, error) {
				args, reserved, err := toolrpc.Decode(text)
				started := time.Now()
				entry := audit.Entry{Time: started, Conn: connID(sess.Conn()), User: sess.Conn().User()}
				if !reserved {
					code := execute(sess, text)
					entry.Kind, entry.Args, entry.ExitCode, entry.DurationMS = "exec", []string{text}, audit.Code(code), time.Since(started).Milliseconds()
					log.Write(entry)
					return true, nil
				}
				defer sess.Channel.Close()
				if err != nil {
					finish(sess, 2, err)
					return true, nil
				}
				if handler == nil {
					finish(sess, 1, errors.New("agent tools unavailable on this listener"))
					return true, nil
				}
				toolCtx := audit.WithConnection(serverCtx, log, entry.Conn, entry.User)
				serveTool(toolCtx, sess, args, handler)
				return true, nil
			}, nil, nil
		},
	})
	if err != nil {
		return nil, nil, err
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	l = telemetry.Wrap(l, metrics)
	done := make(chan error, 1)
	go func() { done <- s.StartWithContext(ctx, l) }()
	return l, done, nil
}

// serveTool returns the exit code it reported and any non-exit error.
func serveTool(ctx context.Context, sess *xssh.Session, args []string, handler toolproto.Handler) (int, error) {
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func(base context.Context) {
		select {
		case <-sess.Done():
			cancel()
		case <-base.Done():
		}
	}(requestCtx)
	select {
	case size := <-sess.Resizes:
		if len(size) == 8 {
			requestCtx = toolproto.WithTerminal(requestCtx, toolproto.Terminal{Cols: binary.BigEndian.Uint32(size[:4]), Rows: binary.BigEndian.Uint32(size[4:]), Resizes: sess.Resizes})
		}
	default:
	}
	err := handler(requestCtx, args, sess.Channel, sess.Channel, sess.Channel.Stderr())
	var code toolproto.ExitError
	var pointer *toolproto.ExitError
	if errors.As(err, &code) || errors.As(err, &pointer) {
		finish(sess, toolproto.ExitCode(err), nil)
		return toolproto.ExitCode(err), nil
	}
	finish(sess, toolproto.ExitCode(err), err)
	return toolproto.ExitCode(err), err
}

// execute runs a plain exec request and returns its exit code; -1 means the
// client disconnected first and the process tree was stopped.
func execute(sess *xssh.Session, text string) int {
	defer sess.Channel.Close()
	// Plain "ssh host 'script'" shares the run tool's wrapper and its fixes.
	cmd, cleanup, err := execsvc.ShellCommand(sess.Config().Shell, text, false)
	if err != nil {
		finish(sess, 1, err)
		return 1
	}
	defer cleanup()
	cmd.Dir, cmd.Env = sess.Config().WorkingDirectory, sess.Env
	cmd.Stdout, cmd.Stderr = sess.Channel, sess.Channel.Stderr()
	cmd.WaitDelay = 2 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		finish(sess, 1, err)
		return 1
	}
	stop, err := platform.Start(cmd)
	if err != nil {
		stdin.Close()
		finish(sess, 1, err)
		return 1
	}
	defer func() { stop() }()
	go func() { _, _ = io.Copy(stdin, sess.Channel); _ = stdin.Close() }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-sess.Done():
		stop()
		// stop must be invoked once (a Windows handle may be reused).
		stop = func() {}
		<-done
		return -1
	}
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = execsvc.SignedExit(exitErr.ExitCode())
	} else if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		code = 1
	}
	finish(sess, code, nil)
	return code
}

func finish(sess *xssh.Session, code int, err error) {
	if err != nil {
		_, _ = fmt.Fprintln(sess.Channel.Stderr(), "assh:", err)
	}
	_, _ = sess.Channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(code)}))
}
