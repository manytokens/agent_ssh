// Package execsvc implements shell execution and service-owned sessions/jobs.
package execsvc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"agent_ssh/internal/platform"
	"agent_ssh/internal/toolproto"
)

const outputLimit = 4 << 20

type Service struct {
	shell, workdir, stateDir string
	ctx                      context.Context
	cancel                   context.CancelFunc
	mu                       sync.Mutex
	tasks                    map[string]*task
	closed                   bool
	wg                       sync.WaitGroup
}

func New(shell, workdir, stateDir string) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{shell: shell, workdir: workdir, stateDir: stateDir, ctx: ctx, cancel: cancel, tasks: make(map[string]*task)}
	s.loadHistory()
	s.pruneJobs()
	if stateDir != "" {
		s.reapOrphans()
		s.wg.Add(1)
		go s.trackProcesses()
		s.wg.Add(1)
		go s.maintainJobs()
	}
	return s
}

// Running counts live sessions and jobs, for the status tool.
func (s *Service) Running() (sessions, jobs int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tasks {
		select {
		case <-t.done:
			continue
		default:
		}
		if t.kind == "session" {
			sessions++
		} else {
			jobs++
		}
	}
	return
}

// processFile records live command processes. After a crash of the previous
// instance, the next start ends those still running (see platform.Tracked).
func (s *Service) processFile() string { return filepath.Join(s.stateDir, "processes.json") }

func (s *Service) reapOrphans() {
	b, err := os.ReadFile(s.processFile())
	if err != nil {
		return
	}
	var records []platform.Record
	if json.Unmarshal(b, &records) == nil {
		platform.KillRecorded(records)
	}
	os.Remove(s.processFile())
}

func (s *Service) trackProcesses() {
	defer s.wg.Done()
	defer os.Remove(s.processFile())
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	last := ""
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
		}
		records := platform.Tracked()
		b, _ := json.Marshal(records)
		if string(b) == last {
			continue
		}
		last = string(b)
		if len(records) == 0 {
			os.Remove(s.processFile())
		} else {
			tmp := s.processFile() + ".tmp"
			if os.WriteFile(tmp, b, 0600) == nil {
				os.Rename(tmp, s.processFile())
			}
		}
	}
}

func (s *Service) Close() error {
	s.mu.Lock()
	s.closed = true
	tasks := make([]*task, 0, len(s.tasks))
	for _, t := range s.tasks {
		tasks = append(tasks, t)
	}
	s.mu.Unlock()
	for _, t := range tasks {
		t.mu.Lock()
		if t.kind == "job" && t.finished.IsZero() {
			t.interrupted = true
		}
		t.mu.Unlock()
	}
	s.cancel()
	for _, t := range tasks {
		t.kill()
	}
	for _, t := range tasks {
		<-t.done
	}
	s.wg.Wait()
	return nil
}

type options struct {
	shell, cwd string
	timeout    time.Duration
	json, dry  bool
	pty        bool
	separated  bool // argv followed an explicit --
	cols, rows uint16
	argv       []string
}

func parse(args []string) (o options, err error) {
	// A standalone dry-run flag remains effective after the script/argv.
	// Use -- to pass a literal --dry-run argument to the child instead.
	var clean []string
	for i, a := range args {
		if a == "--" {
			clean = append(clean, args[i:]...)
			break
		}
		if a == "--dry-run" {
			o.dry = true
			continue
		}
		clean = append(clean, a)
	}
	args = clean
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			o.argv = append(o.argv, args[i+1:]...)
			o.separated = true
			break
		}
		flag := a
		inline := ""
		hasInline := false
		if k, v, ok := strings.Cut(a, "="); ok {
			switch k {
			case "--timeout", "--cwd", "--shell", "--cols", "--rows":
				flag = k
				inline = v
				hasInline = true
			}
		}
		value := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", a)
			}
			i++
			return args[i], nil
		}
		switch flag {
		case "--json":
			o.json = true
		case "--dry-run":
			o.dry = true
		case "--pty":
			o.pty = true
		case "--cols", "--rows":
			v, e := value()
			if e != nil {
				return o, e
			}
			n, e := strconv.ParseUint(v, 10, 16)
			if e != nil || n == 0 {
				return o, errors.New("terminal dimension must be 1..32767")
			}
			if n > 32767 {
				return o, errors.New("terminal dimension must be 1..32767")
			}
			if flag == "--cols" {
				o.cols = uint16(n)
			} else {
				o.rows = uint16(n)
			}
		case "--timeout":
			var v string
			v, err = value()
			if err == nil {
				o.timeout, err = time.ParseDuration(v)
				if err != nil {
					var n float64
					n, err = strconv.ParseFloat(v, 64)
					o.timeout = time.Duration(n * float64(time.Second))
				}
				if o.timeout <= 0 && err == nil {
					err = errors.New("timeout must be positive")
				}
			}
		case "--cwd":
			o.cwd, err = value()
		case "--shell":
			o.shell, err = value()
		default:
			o.argv = append(o.argv, args[i:]...)
			return o, nil
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

func encodePowerShell(text string) string {
	u := utf16.Encode([]rune(text))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return base64.StdEncoding.EncodeToString(b)
}
func powerShell(shell string) bool {
	b := strings.ToLower(strings.TrimSuffix(filepath.Base(shell), ".exe"))
	return b == "pwsh" || b == "powershell"
}
func resolveShell(shell string) (string, error) {
	if shell == "" {
		if runtime.GOOS == "windows" {
			for _, v := range []string{"pwsh.exe", "powershell.exe"} {
				if p, e := exec.LookPath(v); e == nil {
					return p, nil
				}
			}
			return "", errors.New("PowerShell not installed")
		}
		shell = "bash"
	}
	if shell == "bash" || shell == "git-bash" {
		return BashPath()
	}
	return exec.LookPath(shell)
}

// BashPath deliberately never picks Windows System32 bash.exe (the WSL shim).
func BashPath() (string, error) {
	if runtime.GOOS != "windows" {
		return exec.LookPath("bash")
	}
	candidates := []string{}
	if p, e := exec.LookPath("git.exe"); e == nil {
		root := filepath.Dir(filepath.Dir(p))
		candidates = append(candidates, filepath.Join(root, "bin", "bash.exe"), filepath.Join(root, "usr", "bin", "bash.exe"))
	}
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs")} {
		candidates = append(candidates, filepath.Join(root, "Git", "bin", "bash.exe"))
	}
	for _, p := range candidates {
		if f, e := os.Stat(p); e == nil && !f.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("Git Bash not found; install Git for Windows or specify --shell with its bash.exe path")
}

// psWrapper loads the user script from a UTF-8 file rather than the command
// line, so script size is not bound by the 32K-character Windows limit and
// parse errors are catchable. Piping through Out-Default flushes formatted
// output (Format-Table buffers objects) before exit runs. The appended line
// records $? of the script's last statement, which is how a failing native
// command at the end of the script reaches the exit code.
func psWrapper(path string) string {
	q := strings.ReplaceAll(path, "'", "''")
	return "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $OutputEncoding=[Console]::OutputEncoding; if ($PSStyle) { $PSStyle.OutputRendering='PlainText' }; $global:LASTEXITCODE=0; $global:__assh_ok=$true\n" +
		// Parse the script alone first so syntax errors report the user's own
		// line and column, without the Create() method-call wrapper message.
		"try { $__assh_text=[IO.File]::ReadAllText('" + q + "', [Text.UTF8Encoding]::new($false)); Remove-Item -LiteralPath '" + q + "' -Force -ErrorAction SilentlyContinue; $null=[scriptblock]::Create($__assh_text) } catch { $__assh_e=$_.Exception; if ($__assh_e.InnerException) { $__assh_e=$__assh_e.InnerException }; [Console]::Error.WriteLine($__assh_e.Message); exit 1 }\n" +
		"try { & ([scriptblock]::Create($__assh_text + \"`n`$global:__assh_ok=`$?\")) | Out-Default } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }\n" +
		"if (-not $global:__assh_ok) { if ($global:LASTEXITCODE) { exit $global:LASTEXITCODE }; exit 1 }; exit 0"
}

// ShellCommand builds the process that runs script text in shell, for run,
// jobs and plain SSH exec alike. PowerShell gets the script-file wrapper,
// cmd.exe /d /s /c, any other shell -c. The cleanup function removes the
// script file; a dry run writes none and its argv names a placeholder.
func ShellCommand(shell, text string, dry bool) (*exec.Cmd, func(), error) {
	if powerShell(shell) {
		path := filepath.Join(os.TempDir(), "assh-SCRIPT.ps1")
		cleanup := func() {}
		if !dry {
			f, e := os.CreateTemp("", "assh-*.ps1")
			if e != nil {
				return nil, nil, e
			}
			path = f.Name()
			_, e = f.WriteString(text)
			if ce := f.Close(); e == nil {
				e = ce
			}
			if e != nil {
				os.Remove(path)
				return nil, nil, e
			}
			cleanup = func() { os.Remove(path) }
		}
		return exec.Command(shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", encodePowerShell(psWrapper(path))), cleanup, nil
	}
	if strings.EqualFold(strings.TrimSuffix(filepath.Base(shell), ".exe"), "cmd") {
		return exec.Command(shell, "/d", "/s", "/c", text), func() {}, nil
	}
	return exec.Command(shell, "-c", text), func() {}, nil
}

// command returns a cleanup function that removes any script file it wrote.
// A dry run never writes the file; its argv names a placeholder path.
func (s *Service) command(kind string, o options) (*exec.Cmd, func(), error) {
	cleanup := func() {}
	cwd := o.cwd
	if cwd == "" {
		cwd = s.workdir
	}
	var cmd *exec.Cmd
	switch kind {
	case "bash":
		p, e := BashPath()
		if o.shell != "" {
			p, e = exec.LookPath(o.shell)
		}
		if e != nil {
			return nil, nil, e
		}
		a := o.argv
		if len(a) == 0 {
			a = []string{"--noprofile", "--norc", "-i"}
		}
		cmd = exec.Command(p, a...)
	case "wsl":
		// --cwd is a Linux/WSL directory, not the Windows process's cwd.
		cwd = s.workdir
		if runtime.GOOS != "windows" {
			return nil, nil, errors.New("wsl requires Windows with WSL installed")
		}
		p, e := exec.LookPath("wsl.exe")
		if e != nil {
			return nil, nil, errors.New("wsl.exe not found; install WSL and a distribution")
		}
		a := []string{}
		if o.cwd != "" {
			a = append(a, "--cd", o.cwd)
		}
		a = append(a, o.argv...)
		cmd = exec.Command(p, a...)
	default:
		sh := o.shell
		if sh == "" {
			sh = s.shell
		}
		p, e := resolveShell(sh)
		if e != nil {
			return nil, nil, e
		}
		if len(o.argv) == 0 {
			return nil, nil, errors.New("run requires a command script")
		}
		if !o.separated && strings.HasPrefix(o.argv[0], "--") {
			return nil, nil, fmt.Errorf("unknown option %s (put -- before a script that begins with --)", o.argv[0])
		}
		if cmd, cleanup, e = ShellCommand(p, strings.Join(o.argv, " "), o.dry); e != nil {
			return nil, nil, e
		}
	}
	if kind != "wsl" {
		// Report a missing directory by name; CreateProcess only says "invalid".
		if i, e := os.Stat(cwd); e != nil || !i.IsDir() {
			cleanup()
			return nil, nil, fmt.Errorf("working directory not found: %s", cwd)
		}
	}
	cmd.Dir = cwd
	cmd.Env = os.Environ()
	if kind == "bash" && runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "CHERE_INVOKING=1")
	}
	if kind == "wsl" {
		// wsl.exe writes its own messages in UTF-16 unless asked for UTF-8.
		cmd.Env = append(cmd.Env, "WSL_UTF8=1")
	}
	cmd.WaitDelay = 2 * time.Second
	return cmd, cleanup, nil
}

// dryPlan describes a command without running it. Script text is included
// because a PowerShell argv only carries an encoded wrapper.
func dryPlan(kind string, cmd *exec.Cmd, o options) map[string]any {
	plan := map[string]any{"dry_run": true, "argv": cmd.Args, "cwd": cmd.Dir, "timeout_seconds": o.timeout.Seconds(), "note": "No command was executed. Arbitrary script side effects are not inferred."}
	if kind != "bash" && kind != "wsl" {
		plan["script"] = strings.Join(o.argv, " ")
	}
	return plan
}

type Result struct {
	Stdout       string  `json:"stdout"`
	Stderr       string  `json:"stderr"`
	ExitCode     int     `json:"exit_code"`
	Duration     float64 `json:"duration"`
	TimedOut     bool    `json:"timed_out"`
	Truncated    bool    `json:"truncated"`
	Binary       bool    `json:"binary,omitempty"`
	StdoutBase64 string  `json:"stdout_base64,omitempty"`
}

func code(err error) int {
	if err == nil {
		return 0
	}
	var e *exec.ExitError
	if errors.As(err, &e) {
		if n := e.ExitCode(); n >= 0 {
			return SignedExit(n)
		}
	}
	return 1
}

// SignedExit maps a Windows DWORD exit status to the int32 the program
// returned, so exit -1 reports -1 rather than 4294967295.
func SignedExit(n int) int {
	if runtime.GOOS == "windows" && n > 0x7fffffff {
		return int(int32(uint32(n)))
	}
	return n
}
func exit(code int) error {
	if code == 0 {
		return nil
	}
	return &toolproto.ExitError{Code: code}
}
func jsonOut(out io.Writer, v any) error { return json.NewEncoder(out).Encode(v) }

func (s *Service) Handle(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("execution service closed")
	}
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopService := context.AfterFunc(s.ctx, cancel)
	defer stopService()
	if len(args) == 0 {
		return errors.New("expected run, exec, bash, wsl, session or job")
	}
	if in == nil {
		in = strings.NewReader("")
	}
	switch args[0] {
	case "session", "job":
		return s.taskCommand(ctx, args[0], args[1:], in, out, stderr)
	case "run", "exec", "bash", "wsl", "shell":
	default:
		return errors.New("unknown execution command: " + args[0])
	}
	o, e := parse(args[1:])
	if e != nil {
		return e
	}
	term, hasTerm := toolproto.TerminalFromContext(ctx)
	if args[0] == "shell" && !hasTerm && !o.pty && !o.dry {
		return errors.New("interactive shell requires a PTY; connect with ssh -tt")
	}
	if o.pty || args[0] == "shell" || (hasTerm && (args[0] == "bash" || args[0] == "wsl")) {
		resize := make(chan Size, 1)
		childCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			defer close(resize)
			for {
				select {
				case b, ok := <-term.Resizes:
					if !ok {
						return
					}
					if len(b) >= 8 {
						z := Size{uint16(binary.BigEndian.Uint32(b)), uint16(binary.BigEndian.Uint32(b[4:]))}
						select {
						case resize <- z:
						case <-childCtx.Done():
							return
						}
					}
				case <-childCtx.Done():
					return
				}
			}
		}()
		return s.HandlePTY(childCtx, args, in, out, stderr, Size{uint16(term.Cols), uint16(term.Rows)}, resize)
	}
	cmd, cleanup, e := s.command(args[0], o)
	if e != nil {
		return e
	}
	defer cleanup()
	if o.dry {
		return jsonOut(out, dryPlan(args[0], cmd, o))
	}
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}
	started := time.Now()
	ob, eb := &logBuffer{}, &logBuffer{}
	if o.json {
		cmd.Stdout = ob
		cmd.Stderr = eb
	} else {
		cmd.Stdout = out
		cmd.Stderr = stderr
	}
	// StdinPipe avoids exec.Wait waiting on an arbitrary request reader after the child exits.
	input, e := cmd.StdinPipe()
	if e != nil {
		return e
	}
	stop, e := platform.Start(cmd)
	if e != nil {
		input.Close()
		return e
	}
	var once sync.Once
	kill := func() { once.Do(stop) }
	defer kill()
	go func() { io.Copy(input, in); input.Close() }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timed := false
	select {
	case e = <-done:
	case <-ctx.Done():
		timed = errors.Is(ctx.Err(), context.DeadlineExceeded)
		kill()
		e = <-done
	}
	n := code(e)
	if timed {
		n = 124
	}
	if o.json {
		a, _, ta := ob.snapshot(0)
		b, _, tb := eb.snapshot(0)
		r := Result{Stdout: a, Stderr: b, ExitCode: n, Duration: time.Since(started).Seconds(), TimedOut: timed, Truncated: ta || tb}
		// JSON strings cannot carry arbitrary bytes; keep them exact in base64.
		if !utf8.ValidString(a) {
			r.Binary, r.StdoutBase64, r.Stdout = true, base64.StdEncoding.EncodeToString([]byte(a)), strings.ToValidUTF8(a, "\ufffd")
		}
		if err := jsonOut(out, r); err != nil {
			return err
		}
	}
	return exit(n)
}

// logBuffer retains the last 4 MiB. Absolute offsets make truncation visible.
type logBuffer struct {
	mu      sync.Mutex
	b       []byte
	base    int64
	notify  chan struct{}
	discard bool
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.discard {
		b.base += int64(n)
	} else {
		b.b = append(b.b, p...)
	}
	if len(b.b) > outputLimit {
		drop := len(b.b) - outputLimit
		b.b = append([]byte(nil), b.b[drop:]...)
		b.base += int64(drop)
	}
	if b.notify != nil {
		close(b.notify)
	}
	b.notify = make(chan struct{})
	return n, nil
}
func (b *logBuffer) snapshot(offset int64) (string, int64, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	truncated := offset < b.base
	if offset < b.base {
		offset = b.base
	}
	end := b.base + int64(len(b.b))
	if offset > end {
		offset = end
	}
	return string(bytes.Clone(b.b[offset-b.base:])), end, truncated
}

// Keep a partial trailing rune for the next text poll. Raw terminal streams
// continue to use snapshot, which must forward every byte immediately.
func trimIncompleteUTF8(s string) string {
	if len(s) == 0 {
		return s
	}
	start := len(s) - 1
	for start > 0 && !utf8.RuneStart(s[start]) {
		start--
	}
	if !utf8.FullRuneInString(s[start:]) {
		return s[:start]
	}
	return s
}

func (b *logBuffer) textSnapshot(offset int64, final bool) (string, int64, bool) {
	a, next, truncated := b.snapshot(offset)
	if !final {
		complete := trimIncompleteUTF8(a)
		next -= int64(len(a) - len(complete))
		a = complete
	}
	return a, next, truncated
}

// Invalid bytes (including terminal/binary output) remain recoverable even
// though JSON text itself requires valid UTF-8.
func setStreamResult(m map[string]any, stream, raw string) {
	m[stream] = strings.ToValidUTF8(raw, "\ufffd")
	delete(m, stream+"_base64")
	if !utf8.ValidString(raw) {
		m[stream+"_base64"] = base64.StdEncoding.EncodeToString([]byte(raw))
	}
}
func (b *logBuffer) changed() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.notify == nil {
		b.notify = make(chan struct{})
	}
	return b.notify
}

type task struct {
	id, kind         string
	cmd              *exec.Cmd
	input            io.WriteCloser
	writeMu          sync.Mutex
	stdout, stderr   logBuffer
	done             chan struct{}
	kill             func()
	started          time.Time
	mu               sync.Mutex
	exitCode         int
	timedOut         bool
	terminal         terminal
	finished         time.Time
	diskOut, diskErr *jobLog
	logTruncated     bool
	logMu            sync.Mutex
	logDir           string
	interrupted      bool
	cleanup          func()
}

func (t *task) result(offset int64) map[string]any {
	if t.logDir != "" {
		return t.diskResult(offset, 0)
	}
	return t.resultMemory(offset)
}
func (t *task) resultMemory(offset int64) map[string]any {
	running := true
	select {
	case <-t.done:
		running = false
	default:
	}
	a, next, tr := t.stdout.textSnapshot(offset, !running)
	b, _, te := t.stderr.textSnapshot(0, !running)
	t.mu.Lock()
	n, to := t.exitCode, t.timedOut
	interrupted := t.interrupted
	duration := time.Since(t.started).Seconds()
	if !t.finished.IsZero() {
		duration = t.finished.Sub(t.started).Seconds()
	}
	t.mu.Unlock()
	m := map[string]any{"id": t.id, "kind": t.kind, "running": running, "offset": next, "truncated": tr || te, "exit_code": n, "timed_out": to, "duration": duration, "pty": t.terminal != nil, "interrupted": interrupted}
	setStreamResult(m, "stdout", a)
	setStreamResult(m, "stderr", b)
	return m
}

func (s *Service) startTask(kind string, o options) (t *task, err error) {
	var cmd *exec.Cmd
	scriptCleanup := func() {}
	if kind == "session" {
		sh := o.shell
		if sh == "" {
			sh = s.shell
		}
		p, e := resolveShell(sh)
		if e != nil {
			return nil, e
		}
		if powerShell(p) {
			cmd = exec.Command(p, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-")
		} else {
			cmd = exec.Command(p, "--noprofile", "--norc")
		}
		if o.pty {
			if powerShell(p) {
				cmd = exec.Command(p, "-NoLogo", "-NoProfile")
			} else {
				cmd = exec.Command(p, "--noprofile", "--norc", "-i")
			}
		}
		cmd.Dir = o.cwd
		if cmd.Dir == "" {
			cmd.Dir = s.workdir
		}
		cmd.Env = append(os.Environ(), "TERM=dumb")
		if o.pty {
			cmd.Env = append(os.Environ(), "TERM=xterm-256color")
		}
		if !powerShell(p) && runtime.GOOS == "windows" {
			cmd.Env = append(cmd.Env, "CHERE_INVOKING=1")
		}
		cmd.WaitDelay = 2 * time.Second
	} else {
		cmd, scriptCleanup, err = s.command("run", o)
		if err != nil {
			return nil, err
		}
		// A started job removes its script after exit; failures remove it now.
		defer func() {
			if err != nil {
				scriptCleanup()
			}
		}()
	}
	b := make([]byte, 12)
	if _, err = rand.Read(b); err != nil {
		return nil, err
	}
	created := &task{id: hex.EncodeToString(b), kind: kind, cmd: cmd, done: make(chan struct{}), started: time.Now(), cleanup: scriptCleanup}
	if err = s.prepareDisk(created); err != nil {
		return nil, err
	}
	if o.pty {
		return s.startPTYTask(created, o)
	}
	t = created
	cmd.Stdout = &t.stdout
	cmd.Stderr = &t.stderr
	if t.diskOut != nil {
		cmd.Stdout = io.MultiWriter(t.diskOut, &t.stdout)
		cmd.Stderr = io.MultiWriter(t.diskErr, &t.stderr)
	}
	t.input, err = cmd.StdinPipe()
	if err != nil {
		t.closeDisk()
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		t.input.Close()
		t.closeDisk()
		return nil, errors.New("execution service closed")
	}
	stop, err := platform.Start(cmd)
	if err != nil {
		t.input.Close()
		t.closeDisk()
		return nil, err
	}
	var once sync.Once
	t.kill = func() { once.Do(func() { stop(); t.input.Close() }) }
	s.tasks[t.id] = t
	go func() {
		err := cmd.Wait()
		t.mu.Lock()
		if t.interrupted {
			t.exitCode = 130
		} else if t.timedOut {
			t.exitCode = 124
		} else {
			t.exitCode = code(err)
		}
		t.finished = time.Now()
		t.mu.Unlock()
		t.kill()
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
			return
		case <-s.ctx.Done():
			t.kill()
		case <-timeout:
			t.mu.Lock()
			t.timedOut = true
			t.exitCode = 124
			t.mu.Unlock()
			t.kill()
		}
	}()
	if kind == "session" && powerShell(cmd.Path) {
		t.input.Write([]byte("$ProgressPreference='SilentlyContinue'; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $OutputEncoding=[Console]::OutputEncoding\n"))
	}
	if kind == "job" {
		_ = t.input.Close()
	}
	return t, nil
}

func (s *Service) taskCommand(ctx context.Context, kind string, args []string, in io.Reader, out, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("%s requires an action", kind)
	}
	action := args[0]
	if kind == "job" && (action == "clean" || action == "remove") {
		return s.manageJobs(args, out)
	}
	// Normalize may place global flags immediately after the action. Detect a
	// preview before IDs, stdin reads, waits, attach, or any task mutation.
	if action != "new" && action != "start" {
		for _, a := range args[1:] {
			if a == "--" {
				break
			}
			if a == "--dry-run" {
				return jsonOut(out, map[string]any{"dry_run": true, "kind": kind, "action": action, "argv": args[1:]})
			}
		}
	}
	if action == "new" || action == "start" {
		o, e := parse(args[1:])
		if e != nil {
			return e
		}
		if o.dry {
			if kind == "job" {
				cmd, _, e := s.command("run", o)
				if e != nil {
					return e
				}
				return jsonOut(out, dryPlan("run", cmd, o))
			}
			sh := o.shell
			if sh == "" {
				sh = s.shell
			}
			p, e := resolveShell(sh)
			if e != nil {
				return e
			}
			argv := []string{p, "--noprofile", "--norc"}
			if powerShell(p) {
				argv = []string{p, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"}
				if o.pty {
					argv = []string{p, "-NoLogo", "-NoProfile"}
				}
			} else if o.pty {
				argv = append(argv, "-i")
			}
			cwd := o.cwd
			if cwd == "" {
				cwd = s.workdir
			}
			return jsonOut(out, map[string]any{"dry_run": true, "argv": argv, "cwd": cwd, "pty": o.pty, "timeout_seconds": o.timeout.Seconds()})
		}
		t, e := s.startTask(kind, o)
		if e != nil {
			return e
		}
		return jsonOut(out, t.result(0))
	}
	if action == "list" {
		s.mu.Lock()
		defer s.mu.Unlock()
		items := []map[string]any{}
		for _, t := range s.tasks {
			if t.kind == kind {
				m := t.resultMemory(0)
				if kind == "job" {
					m["log_truncated"] = t.logTruncated || t.diskOut.Truncated() || t.diskErr.Truncated()
				}
				delete(m, "stdout")
				delete(m, "stderr")
				delete(m, "stdout_base64")
				delete(m, "stderr_base64")
				delete(m, "offset")
				delete(m, "truncated")
				items = append(items, m)
			}
		}
		return jsonOut(out, items)
	}
	if len(args) < 2 {
		return fmt.Errorf("%s %s requires an ID", kind, action)
	}
	s.mu.Lock()
	t := s.tasks[args[1]]
	s.mu.Unlock()
	if t == nil || t.kind != kind {
		return errors.New("unknown " + kind + " ID")
	}
	offset := int64(0)
	stderrOffset := int64(0)
	wait := time.Duration(0)
	rest := []string{}
	dry := false
	var timeout time.Duration
	for i := 2; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			dry = true
		case "--json":
		case "--timeout":
			i++
			if i >= len(args) {
				return errors.New("--timeout requires value")
			}
			opts, err := parse([]string{"--timeout", args[i]})
			if err != nil {
				return err
			}
			timeout = opts.timeout
		case "--offset", "--stderr-offset", "--wait":
			f := args[i]
			i++
			if i >= len(args) {
				return fmt.Errorf("%s requires value", f)
			}
			var e error
			if f == "--offset" {
				offset, e = strconv.ParseInt(args[i], 10, 64)
			} else if f == "--stderr-offset" {
				stderrOffset, e = strconv.ParseInt(args[i], 10, 64)
			} else {
				wait, e = time.ParseDuration(args[i])
			}
			if e != nil || offset < 0 || stderrOffset < 0 {
				return errors.New("invalid offset or wait")
			}
		default:
			rest = append(rest, args[i])
		}
	}
	if dry {
		return jsonOut(out, map[string]any{"dry_run": true, "action": action, "id": t.id, "input": strings.Join(rest, " ")})
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	result := func() map[string]any {
		if t.logDir != "" {
			return t.diskResult(offset, stderrOffset)
		}
		m := t.result(offset)
		b, next, tr := t.stderr.textSnapshot(stderrOffset, m["running"] == false)
		setStreamResult(m, "stderr", b)
		m["stderr_offset"] = next
		if tr {
			m["truncated"] = true
		}
		return m
	}
	switch action {
	case "send":
		text := strings.Join(rest, " ")
		if len(rest) == 0 {
			b, e := io.ReadAll(io.LimitReader(in, 1<<20+1))
			if e != nil {
				return e
			}
			if len(b) > 1<<20 {
				return errors.New("session send exceeds 1 MiB")
			}
			text = string(b)
		}
		t.writeMu.Lock()
		ending := "\n"
		if t.terminal != nil {
			ending = "\r"
		} else if strings.Contains(text, "\n") && powerShell(t.cmd.Path) && !strings.HasSuffix(text, "\n\n") {
			// "pwsh -Command -" ends a multi-line statement only at a blank line.
			ending = "\n\n"
		}
		_, e := io.WriteString(t.input, text+ending)
		t.writeMu.Unlock()
		if e != nil {
			return e
		}
		return jsonOut(out, map[string]any{"id": t.id, "sent": true})
	case "read", "log":
		if wait > 0 {
			change := t.stdout.changed()
			errChange := t.stderr.changed()
			a, _, _ := t.stdout.snapshot(offset)
			b, _, _ := t.stderr.snapshot(stderrOffset)
			if t.logDir != "" {
				if st, e := os.Stat(filepath.Join(t.logDir, "stdout.log")); e == nil && st.Size() > offset {
					a = "available"
				}
				if st, e := os.Stat(filepath.Join(t.logDir, "stderr.log")); e == nil && st.Size() > stderrOffset {
					b = "available"
				}
			}
			if a == "" && b == "" {
				timer := time.NewTimer(wait)
				defer timer.Stop()
				select {
				case <-change:
				case <-errChange:
				case <-t.done:
				case <-ctx.Done():
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		return jsonOut(out, result())
	case "wait":
		select {
		case <-t.done:
		case <-ctx.Done():
			return ctx.Err()
		}
		return jsonOut(out, result())
	case "close", "kill":
		t.kill()
		<-t.done
		return jsonOut(out, result())
	case "attach":
		if kind != "session" {
			return errors.New("job output is read with job log; only sessions can be attached")
		}
		attachCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go resizeAttached(attachCtx, t)
		inputDone := make(chan struct{})
		// A request disconnect detaches, retaining the service-owned shell.
		go func() {
			defer close(inputDone)
			buf := make([]byte, 8192)
			for {
				n, e := in.Read(buf)
				if n > 0 {
					t.writeMu.Lock()
					_, werr := t.input.Write(buf[:n])
					t.writeMu.Unlock()
					if werr != nil {
						return
					}
				}
				if e != nil {
					return
				}
			}
		}()
		for {
			change := t.stdout.changed()
			errChange := t.stderr.changed()
			a, next, _ := t.stdout.snapshot(offset)
			if _, e := io.WriteString(out, a); e != nil {
				return e
			}
			offset = next
			b, en, _ := t.stderr.snapshot(stderrOffset)
			if _, e := io.WriteString(stderr, b); e != nil {
				return e
			}
			stderrOffset = en
			select {
			case <-change:
			case <-errChange:
			case <-inputDone:
				return nil
			case <-t.done:
				a, _, _ := t.stdout.snapshot(offset)
				io.WriteString(out, a)
				b, _, _ := t.stderr.snapshot(stderrOffset)
				io.WriteString(stderr, b)
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	default:
		return errors.New("unknown " + kind + " action " + action)
	}
}
