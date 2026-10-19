package tunnel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"agent_ssh/internal/reverseagent"
	"agent_ssh/internal/toolrpc"
)

func TestRelayToolArgumentsSurviveBash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture: native Windows login and relay wrappers are covered by the SSH integration harness; PATH bash.exe may be the WSL shim")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("Bash unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte("#!/bin/bash\nprintf '%s\\0' \"$@\" > \"$ASSH_TEST_CAPTURE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(dir, "capture")
	c := Config{RemotePort: 22224}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
	command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "ASSH_TEST_CAPTURE="+capture)
	command.Stdin = strings.NewReader(c.RelayShellScript() + "\nassh run '' '中文 $x' \"line\nsecond\"\n")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("relay shell: %v: %s", err, out)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	got, ok, err := toolrpc.Decode(args[len(args)-1])
	if err != nil || !ok {
		t.Fatalf("missing RPC: %q %v", args, err)
	}
	if strings.Join(got, "|") != "run||中文 $x|line\nsecond" {
		t.Fatalf("arguments changed: %#v", got)
	}
	interactive := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
	interactive.Env = command.Env
	interactive.Stdin = strings.NewReader(c.RelayShellScript() + "\nassh\n")
	if out, err := interactive.CombinedOutput(); err != nil {
		t.Fatalf("interactive wrapper: %v %s", err, out)
	}
	data, err = os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	args = strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
	got, ok, err = toolrpc.Decode(args[len(args)-1])
	if err != nil || !ok || strings.Join(got, "|") != "shell|--pty" || args[0] != "-tt" {
		t.Fatalf("shell invocation: %#v %#v %v", args, got, err)
	}
	// asscp gives SFTP the /D:/ drive form; local and relative paths are kept.
	if err := os.WriteFile(filepath.Join(dir, "scp"), []byte("#!/bin/bash\nprintf '%s\\0' \"$@\" > \"$ASSH_TEST_CAPTURE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ args, want string }{
		{`./a 'agent@127.0.0.1:D:/x y/z'`, "./a|agent@127.0.0.1:/D:/x y/z"},
		{`'agent@127.0.0.1:d:\x\y' ./b`, "agent@127.0.0.1:/D:/x/y|./b"},
		{`'agent@127.0.0.1:/d/x' ./c`, "agent@127.0.0.1:/D:/x|./c"},
		{`'agent@127.0.0.1:/e:/x' ./c`, "agent@127.0.0.1:/E:/x|./c"},
		{`'agent@127.0.0.1:D:' ./c`, "agent@127.0.0.1:/D:/|./c"},
		{`'agent@127.0.0.1:rel/dir/f' ./d`, "agent@127.0.0.1:rel/dir/f|./d"},
		{`'agent@127.0.0.1:/tmp/x' D:/local`, "agent@127.0.0.1:/tmp/x|D:/local"},
	} {
		cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
		cmd.Env = command.Env
		cmd.Stdin = strings.NewReader(c.RelayShellScript() + "\nasscp " + tc.args + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("asscp %s: %v %s", tc.args, err, out)
		}
		data, _ := os.ReadFile(capture)
		args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
		if len(args) < 2 || strings.Join(args[len(args)-2:], "|") != tc.want {
			t.Fatalf("asscp %s: %q", tc.args, args)
		}
	}
	// Calls multiplex one connection only through a private runtime directory
	// short enough for a unix socket path.
	runtimeDir, err := os.MkdirTemp("/tmp", "ax")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeDir)
	longDir := filepath.Join(t.TempDir(), strings.Repeat("d", 41))
	if err := os.Mkdir(longDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		env []string
		mux bool
	}{
		{[]string{"XDG_RUNTIME_DIR=" + runtimeDir}, true},
		{[]string{"XDG_RUNTIME_DIR=" + runtimeDir, "ASSH_NO_MUX=1"}, false},
		{[]string{"XDG_RUNTIME_DIR="}, false},
		{[]string{"XDG_RUNTIME_DIR=" + longDir}, false},
	} {
		cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
		cmd.Env = append(append([]string{}, command.Env...), tc.env...)
		cmd.Stdin = strings.NewReader(c.RelayShellScript() + "\nassh status\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("status %v: %v %s", tc.env, err, out)
		}
		data, _ := os.ReadFile(capture)
		joined := strings.ReplaceAll(string(data), "\x00", " ")
		if got := strings.Contains(joined, "ControlPath="); got != tc.mux || (got && !strings.Contains(joined, "ControlPath="+runtimeDir+"/assh-%C")) {
			t.Fatalf("mux %v: %q", tc.env, joined)
		}
		args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
		if got, ok, _ := toolrpc.Decode(args[len(args)-1]); !ok || strings.Join(got, "|") != "status" {
			t.Fatalf("status is not an RPC: %q", args)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "python3"), []byte("#!/bin/bash\nprintf '%s\\0' \"$@\" > \"$ASSH_TEST_CAPTURE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ command, want string }{
		{"assh --json --dry-run put 'relay source' 'D:/PC target'", "put|relay source|D:/PC target|--dry-run"},
		{"assh dry-run --json get 'D:/PC source' 'relay target'", "get|D:/PC source|relay target|--dry-run"},
		{"assh --json sync 'relay source' 'D:/PC target'", "sync|relay source|D:/PC target"},
	} {
		cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
		cmd.Env = command.Env
		cmd.Stdin = strings.NewReader(c.RelayShellScript() + "\n" + tc.command + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", tc.command, err, out)
		}
		data, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00")
		if len(args) < 3 || args[0] != "-c" || strings.Join(args[2:], "|") != tc.want {
			t.Fatalf("file dispatch %s: %#v", tc.command, args)
		}
	}
}

func TestOptionalConnectionSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX snapshot fixture requires Python and mode 0600 on the same filesystem; covered on the Linux relay")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("Bash unavailable")
	}
	if _, err = exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(t.TempDir(), "connection.json")
	c := Config{RemotePort: 22224, AgentSocket: "/tmp/test ephemeral/socket"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, "--noprofile", "--norc")
	// The user's own forwarded agent (-A) is not the one assh's helpers use.
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=/tmp/user-agent")
	cmd.Stdin = strings.NewReader(c.RelayShellScript() + "\nassh connection --write " + shellQuote(path) + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("snapshot: %v %s", err, out)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if value["ssh_auth_sock"] != "/tmp/test ephemeral/socket" || value["socket_ephemeral"] != true || value["port"] != float64(22224) ||
		!strings.Contains(value["ssh_command"].(string), "IdentityAgent=/tmp/test ephemeral/socket") {
		t.Fatal(value)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions: %v", info.Mode())
	}
}

func TestPortFallbackDoesNotHideOtherSSHFailures(t *testing.T) {
	for _, tc := range []struct {
		message string
		want    bool
	}{
		{"exit status 255: Error: remote port forwarding failed for listen port 22222", true},
		{"remote port forwarding failed for listen port 22223", false},
		{"Permission denied (publickey).", false},
		{"Host key verification failed.", false},
		{"Connection refused", false},
	} {
		if got := forwardingFailed(errors.New(tc.message), 22222); got != tc.want {
			t.Errorf("%q: got %v", tc.message, got)
		}
	}
}

func TestLoginCarriesCompressedRCFile(t *testing.T) {
	c := Config{SSHArgs: []string{"-A", "user@relay", "-L", "8080:localhost:80"}, ForwardAgent: "/tmp/agent", RemotePort: 22224, HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"}
	args := c.LoginArgs()
	// The user's arguments follow unchanged; assh's agent is not forwarded.
	if args[0] != "-tt" || strings.Join(args[len(args)-4:], " ") != "-A user@relay -L 8080:localhost:80" || strings.Contains(strings.Join(args, " "), "ForwardAgent") {
		t.Fatalf("login argv: %v", args)
	}
	var command string
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "RemoteCommand="); ok {
			command = strings.ReplaceAll(value, "%%", "%")
		}
	}
	if c.LoginCommand() != command {
		t.Fatal("RemoteCommand does not carry the escaped login command")
	}
	// Windows limits a whole command line to 32767 characters.
	if !strings.Contains(command, "__assh_decode() { printf %s ") || !strings.Contains(command, "--rcfile /dev/fd/9 -i") || len(command) > 16000 {
		t.Fatalf("login command (%d bytes): %.200s", len(command), command)
	}
	payload := command[strings.Index(command, "printf %s ")+len("printf %s "):]
	payload = payload[:strings.Index(payload, " ")]
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := io.ReadAll(z)
	if string(rc) != c.LoginRC() || !strings.HasPrefix(string(rc), loginProfile) || !strings.Contains(string(rc), c.RelayShellScript()) {
		t.Fatal("rcfile does not carry the profile emulation and helpers")
	}
}

// The login command, run by a POSIX sh as sshd would, yields an interactive
// Bash with the login profile loaded once and the assh helpers defined.
func TestLoginCommandStartsAsshShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX relay fixture")
	}
	for _, tool := range []string{"bash", "base64", "gzip", "sh"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " unavailable")
		}
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".profile"), []byte("printf 'PROFILE_ONCE\\n'\nPS1='TEST> '\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := Config{Destination: "user@relay", ForwardAgent: "/tmp/agent", RemotePort: 22224, HostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", c.LoginCommand())
	rcDir := t.TempDir()
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "SHELL=/bin/sh", "TMPDIR=" + rcDir}
	// Interactive Bash echoes its input, so each marker is computed by the
	// shell: the echo shows "$((40+2))", only real output shows "42".
	cmd.Stdin = strings.NewReader("type assh >/dev/null && type asscp >/dev/null && echo FUNCS_$((40+2)); echo \"PORT=$ASSH_PORT\"; shopt -q login_shell || echo RC_$((50+5)); if { : <&9; } 2>/dev/null; then echo FD9_$((10+1)); else echo FD9_$((10+2)); fi; exit\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("login shell: %v %s", err, out)
	}
	text := string(out)
	// FUNCS_42: helpers defined; RC_55: interactive rcfile shell; FD9_12: the
	// rcfile pipe (fd 9) does not leak into the session's commands.
	if strings.Contains(text, "FD9_11") {
		t.Fatalf("fd 9 leaked into the session: %s", text)
	}
	for _, want := range []string{"FUNCS_42", "PORT=22224", "RC_55", "FD9_12", "assh: connected to"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	if strings.Count(text, "PROFILE_ONCE") != 1 {
		t.Fatalf("profile loaded %d times: %s", strings.Count(text, "PROFILE_ONCE"), text)
	}
	if files, err := os.ReadDir(rcDir); err != nil || len(files) != 0 {
		t.Fatalf("login left bootstrap files: %v %v", files, err)
	}
}

func TestOpenSSHResolvesTunnelAndLoginArguments(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH unavailable")
	}
	agent, err := reverseagent.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer agent.Close()
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
	c := Config{SSHArgs: []string{"-F", "none", "-p2022", "-A", "-L", "8080:localhost:80", "-oServerAliveInterval=3", "example.invalid",
		"-o", "ServerAliveCountMax=3", "-o", "BatchMode=no", "-o", "LocalForward 8081 localhost:81", "-vN"},
		RemotePort: 22222, LocalAddress: "127.0.0.1:12345", ConnectTimeout: 10, ForwardAgent: agent.Endpoint, HostKey: key}
	resolve := func(args []string) string {
		// -G resolves configuration without making any network connection.
		cmd := exec.Command(ssh, append([]string{"-G"}, args...)...)
		cmd.Env = c.Env()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ssh -G: %v: %s", err, out)
		}
		return strings.ReplaceAll(strings.ToLower(string(out)), "\r\n", "\n")
	}
	tunnel := resolve(c.Args())
	for _, expected := range []string{"serveraliveinterval 3", "serveralivecountmax 3", "port 2022", "batchmode yes", "remoteforward [127.0.0.1]:22222 [127.0.0.1]:12345", "loglevel debug", "sessiontype default"} {
		if !strings.Contains(tunnel, expected+"\n") {
			t.Fatalf("tunnel: missing %q in effective OpenSSH configuration:\n%s", expected, tunnel)
		}
	}
	if strings.Contains(tunnel, "localforward") || !strings.Contains(tunnel, "forwardagent "+strings.ToLower(agent.Endpoint)) {
		t.Fatalf("tunnel took the login's forwards or agent:\n%s", tunnel)
	}
	login := resolve(c.LoginArgs())
	for _, expected := range []string{"localforward 8080 [localhost]:80", "localforward 8081 [localhost]:81", "forwardagent yes", "batchmode no", "sessiontype none"} {
		if !strings.Contains(login, expected+"\n") {
			t.Fatalf("login: missing %q:\n%s", expected, login)
		}
	}
}

func TestConnectionArgsSkipSessionOptions(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"-J jump user@relay", "-J jump user@relay"},
		{"-AL 8080:x:80 -D1080 -R 9000:x:90 -fNTtq user@relay -v", "user@relay -v"},
		{"-p2022 -i key -o ForwardAgent=yes -o \"LocalForward 1 x:1\" -oUser=me -4C relay", "-p 2022 -i key -o User=me -4 -C relay"},
		{"-E log -S ctl -W x:1 -O check -e none -Z relay", "-Z relay"},
		{"relay -l me echo -L x", "relay -l me echo -L x"},
		{"-- relay cmd", "-- relay cmd"},
	} {
		in, _ := splitWords(tc.in)
		if got := strings.Join(Config{SSHArgs: in}.ConnectionArgs(), " "); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Without a login (start, run, --no-shell) the tunnel keeps the forwards.
func TestConnectionArgsKeepForwardsWithoutLogin(t *testing.T) {
	in, _ := splitWords("-AL 8080:x:80 -D1080 -N -o \"RemoteForward 9 x:9\" -o ClearAllForwardings=yes relay")
	want := "-L 8080:x:80 -D 1080 -o RemoteForward 9 x:9 relay"
	if got := strings.Join(Config{SSHArgs: in, Forwards: true}.ConnectionArgs(), " "); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// splitWords splits test input on spaces outside double quotes.
func splitWords(s string) ([]string, error) {
	var words []string
	var word strings.Builder
	quoted, any := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted, any = !quoted, true
		case r == ' ' && !quoted:
			if any {
				words = append(words, word.String())
			}
			word.Reset()
			any = false
		default:
			word.WriteRune(r)
			any = true
		}
	}
	if any {
		words = append(words, word.String())
	}
	return words, nil
}

// Readiness needs the matching host key from ssh-keyscan and a working agent;
// without ssh-keyscan it falls back to a full ssh login.
func TestReadyCommandChecksHostKeyAndAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX relay fixture")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
	c := Config{RemotePort: 22224, HostKey: key}
	ready := strings.TrimSuffix(c.ReadyCommand(), "; exec cat")
	if ready == c.ReadyCommand() {
		t.Fatal("ReadyCommand no longer ends with exec cat")
	}
	socketDir, err := os.MkdirTemp("/tmp", "assh-ready-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	agentSock := filepath.Join(socketDir, "agent")
	if l, err := net.Listen("unix", agentSock); err == nil {
		defer l.Close()
	} else {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, scanned string
		keyscan, ok   bool
	}{
		{"matching host key", key, true, true},
		{"other host key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHERKEYOTHE", true, false},
		{"no ssh-keyscan: full login", "", false, true},
	} {
		bin := t.TempDir()
		write := func(name, body string) {
			if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		for _, tool := range []string{"sh", "cat", "sleep", "printf", "test"} {
			if p, err := exec.LookPath(tool); err == nil {
				_ = os.Symlink(p, filepath.Join(bin, tool))
			}
		}
		write("ssh-add", "exit 0")
		write("ssh", "exit 0") // the fallback full login succeeds
		if tc.keyscan {
			write("ssh-keyscan", "echo '# comment'; echo '[127.0.0.1]:22224 "+tc.scanned+"'")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		cmd := exec.CommandContext(ctx, sh, "-c", ready)
		cmd.Env = []string{"PATH=" + bin, "SSH_AUTH_SOCK=" + agentSock}
		out, err := cmd.CombinedOutput()
		cancel()
		if got := err == nil && strings.Contains(string(out), readyMarker); got != tc.ok {
			t.Errorf("%s: ready=%v err=%v out=%s", tc.name, got, err, out)
		}
	}
}
