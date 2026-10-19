package tunnel

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"agent_ssh/internal/filesvc"
	"agent_ssh/internal/toolrpc"
)

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// Env is the environment of the tunnel and probe processes. The login keeps
// the caller's environment, since it does not forward assh's agent.
func (c Config) Env() []string {
	env := os.Environ()
	if c.ForwardAgent == "" {
		return env
	}
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(strings.ToUpper(env[i]), "ASSH_REVERSE_AGENT=") {
			env = append(env[:i], env[i+1:]...)
		}
	}
	// OpenSSH 10.3 checks SSH_AUTH_SOCK before enabling forwarding even when
	// ForwardAgent names a different socket. Headless Unix sessions may have
	// no user agent. Supply our own only in that case; preserve an existing
	// user agent for outbound authentication and all IdentityAgent settings.
	if runtime.GOOS != "windows" && os.Getenv("SSH_AUTH_SOCK") == "" {
		for i := len(env) - 1; i >= 0; i-- {
			if strings.HasPrefix(env[i], "SSH_AUTH_SOCK=") {
				env = append(env[:i], env[i+1:]...)
			}
		}
		env = append(env, "SSH_AUTH_SOCK="+c.ForwardAgent)
	}
	return append(env, "ASSH_REVERSE_AGENT="+c.ForwardAgent)
}

// ReverseOptions verifies the local host from the key delivered through the
// authenticated outer SSH connection. KnownHostsCommand emits it from memory;
// neither known_hosts nor a temporary configuration file is written remotely.
func ReverseOptions(port int, hostKey string) []string {
	fields := strings.Fields(hostKey)
	if len(fields) < 2 {
		return nil
	}
	known := fmt.Sprintf("/bin/echo [127.0.0.1]:%d %s %s", port, fields[0], fields[1])
	return []string{"-F", "/dev/null", "-o", "IdentityFile=none", "-o", "BatchMode=yes", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
		"-o", "UpdateHostKeys=no", "-o", "KnownHostsCommand=" + known}
}

// ReadyCommand verifies the reverse path before the tunnel counts as online.
// Each round trip crosses the relay link twice (often 0.1-1s), so the check
// avoids a full login: ssh-keyscan proves the relay port reaches this
// computer's server (its host key must match), while ssh-add -l proves the
// forwarded agent answers; both run in parallel, about three round trips.
// Without ssh-keyscan, a full login runs the in-process ping tool instead (a
// shell command such as "exit 0" would start PowerShell, itself 1-3 seconds).
func (c Config) ReadyCommand() string {
	login := "ssh -T " + quotedArgs(ReverseOptions(c.RemotePort, c.HostKey)) + fmt.Sprintf(" -p %d agent@127.0.0.1 '%s' >/dev/null", c.RemotePort, toolrpc.Encode([]string{"ping"}))
	probe := login
	if fields := strings.Fields(c.HostKey); len(fields) >= 2 && fields[0] == "ssh-ed25519" {
		scan := fmt.Sprintf("ssh-keyscan -T 5 -t ed25519 -p %d 127.0.0.1 2>/dev/null | while read -r h t k r; do [ \"$h\" = '[127.0.0.1]:%d' ] && printf '%%s %%s' \"$t\" \"$k\"; done", c.RemotePort, c.RemotePort)
		probe = "if command -v ssh-keyscan >/dev/null; then { ssh-add -l >/dev/null 2>&1 & a=$!; [ \"$(" + scan + ")\" = " + shellQuote(fields[0]+" "+fields[1]) + " ]; s=$?; wait $a && [ $s -eq 0 ]; }; else " + login + "; fi"
	}
	return "test -S \"$SSH_AUTH_SOCK\" || { echo 'assh: SSH agent forwarding unavailable' >&2; exit 1; }; " +
		"ok=0; n=0; while [ $n -lt 20 ]; do " + probe + " </dev/null && { ok=1; break; }; n=$((n+1)); sleep 0.1; done; " +
		"[ $ok -eq 1 ] || { echo 'assh: reverse SSH verification failed' >&2; exit 1; }; " +
		"printf 'ASSH_AGENT_SOCKET %s\\n' \"$SSH_AUTH_SOCK\"; printf '" + readyMarker + "\\n'; " +
		// The relay helpers find this session, and so its agent, by this variable.
		fmt.Sprintf("export ASSH_TUNNEL_PORT=%d; exec cat", c.RemotePort)
}

func quotedArgs(args []string) string {
	var quoted []string
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

// RelayShellScript defines the assh helpers and ASSH_* environment in a Bash
// session. The interactive login runs it from LoginRC; tests source it.
func (c Config) RelayShellScript() string {
	// The login may forward the user's own agent (-A), so the helpers name
	// the tunnel's agent explicitly; OpenSSH reads it from this variable.
	opts := quotedArgs(append(ReverseOptions(c.RemotePort, c.HostKey), "-o", "IdentityAgent=$ASSH_AGENT_SOCKET"))
	sshCommand := "ssh " + opts + fmt.Sprintf(" -p %d agent@127.0.0.1", c.RemotePort)
	scpCommand := "scp " + opts + fmt.Sprintf(" -P %d", c.RemotePort)
	connection, _ := json.Marshal(struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		HostKey  string `json:"host_key"`
		TargetOS string `json:"target_os"`
	}{"127.0.0.1", c.RemotePort, "agent", strings.TrimSpace(c.HostKey), runtime.GOOS})
	return fmt.Sprintf(`assh() {
  if [ "$#" -eq 0 ]; then set -- shell; fi
  if [ "${1-}" = connection ] && [ "${2-}" = --write ]; then
    [ "$#" -eq 3 ] || { printf 'usage: assh connection --write PATH\n' >&2; return 2; }
    command -v python3 >/dev/null 2>&1 || { printf 'assh: python3 is required to write connection metadata\n' >&2; return 127; }
    __assh_agent
    command python3 -c %s "$3"
    return
  fi
  local -a __assh_original=("$@") __assh_file_flags=()
  local __assh_file_timeout=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      dry-run|--dry-run) __assh_file_flags+=(--dry-run); shift;;
      --json) shift;;
      --timeout) __assh_file_timeout=1; if [ "$#" -lt 2 ]; then break; fi; shift 2;;
      --timeout=*) __assh_file_timeout=1; shift;;
      *) break;;
    esac
  done
  case "${1-}" in
    put|get|sync)
      [ "$__assh_file_timeout" -eq 0 ] || { printf 'assh: --timeout applies to command execution; relay file transfers do not support it\n' >&2; return 2; }
      command -v python3 >/dev/null 2>&1 || { printf 'assh: python3 is required on the relay for file transfer\n' >&2; return 127; }
      [ -n "${ASSH_FILE_CLIENT-}" ] || { printf 'assh: file transfer helper is unavailable\n' >&2; return 1; }
      __assh_agent
      command python3 -c "$ASSH_FILE_CLIENT" "$@" "${__assh_file_flags[@]}"
      return;;
  esac
  set -- "${__assh_original[@]}"
  __assh_agent
  case "${1-}" in
    shell|run|exec|bash|wsl|fs|info|ps|ports|clip|session|job|watch|help|capabilities|mcp|dry-run|connection|status|--timeout|--timeout=*|--json|--dry-run)
      local __assh_args
      local __assh_tty=-T
      if { [ "$1" = shell ] || [ "$1" = bash ] || [ "$1" = wsl ]; } && [ "$#" -eq 1 ]; then __assh_tty=-tt; set -- "$@" --pty; fi
      if [ "$1" = session ] && [ "${2-}" = attach ] && [ -t 0 ]; then __assh_tty=-tt; fi
      local __assh_arg
      for __assh_arg in "$@"; do if [ "$__assh_arg" = --pty ]; then __assh_tty=-tt; fi; done
      __assh_args=$(printf '%%s\0' "$@" | command base64 | command tr -d '\r\n') || return
      command ssh "$__assh_tty" $(__assh_mux) %s -p %d agent@127.0.0.1 "__assh_rpc_v1 $__assh_args";;
    *) command ssh $(__assh_mux) %s -p %d agent@127.0.0.1 "$@";;
  esac
}
# SFTP takes Windows drives only as /D:/path. Remote arguments written as
# D:/path, d:\path or /d/path are rewritten; local paths are left alone.
__assh_drive() {
  local p=$1 rest drive
  if [[ $p =~ ^/?([A-Za-z]):([/\\].*)?$ ]] || [[ $p =~ ^/([A-Za-z])(/.*)?$ ]]; then
    rest=${BASH_REMATCH[2]}
    rest=${rest//\\//}
    drive=$(printf '%%s' "${BASH_REMATCH[1]}" | command tr '[:lower:]' '[:upper:]')
    p="/$drive:${rest:-/}"
  fi
  printf '%%s' "$p"
}
asscp() {
  local -a __assh_scp=()
  local __assh_a __assh_p
  for __assh_a in "$@"; do
    case "$__assh_a" in
      *@127.0.0.1:*|127.0.0.1:*)
        __assh_p=${__assh_a#*:}
        __assh_a="${__assh_a:0:${#__assh_a}-${#__assh_p}}$(__assh_drive "$__assh_p")";;
    esac
    __assh_scp+=("$__assh_a")
  done
  __assh_agent
  command scp $(__assh_mux) %s -P %d "${__assh_scp[@]}"
}
# Calls share one SSH connection (OpenSSH ControlMaster) instead of a full
# handshake each. The control socket needs a private directory, so this only
# happens with a user-owned XDG_RUNTIME_DIR; the master exits 60s after the
# last call and removes its socket. ASSH_NO_MUX=1 disables it. Unix socket
# paths are limited to 107 bytes and ssh adds a 17-byte suffix while binding,
# so a runtime directory longer than 40 bytes is not used (ssh would fail).
__assh_mux() {
  [ -z "${ASSH_NO_MUX-}" ] && [ -d "${XDG_RUNTIME_DIR-}" ] && [ -O "$XDG_RUNTIME_DIR" ] && [ "${#XDG_RUNTIME_DIR}" -le 40 ] || return 0
  printf '%%s\n' -o ControlMaster=auto -o "ControlPath=$XDG_RUNTIME_DIR/assh-%%C" -o ControlPersist=60
}
# The tunnel's forwarded agent socket changes when it reconnects. Look it up
# before each call in the environment of the tunnel's session process, which
# marks itself with ASSH_TUNNEL_PORT; only the user's own processes are
# readable. Without /proc, keep the last known socket.
__assh_agent() {
  local f s
  for f in $(command grep -lsxzF "ASSH_TUNNEL_PORT=$ASSH_PORT" /proc/[0-9]*/environ 2>/dev/null); do
    s=$(command grep -sz '^SSH_AUTH_SOCK=' "$f" | command tr -d '\0')
    s=${s#SSH_AUTH_SOCK=}
    if [ -S "$s" ] && [ -O "$s" ]; then export ASSH_AGENT_SOCKET="$s"; return 0; fi
  done
  return 0
}
export -f assh asscp __assh_mux __assh_drive __assh_agent
export ASSH_AGENT_SOCKET=%s
export ASSH_PORT=%d
export ASSH_HOST=127.0.0.1 ASSH_USER=agent ASSH_TARGET_OS=%s
export ASSH_HOST_KEY=%s
export ASSH_SSH_COMMAND=%s
export ASSH_SCP_COMMAND=%s
export ASSH_CONNECTION_JSON=%s
export ASSH_AGENT_HELP=%s
export ASSH_FILE_CLIENT=%s`, shellQuote(connectionWriter), opts, c.RemotePort, opts, c.RemotePort, opts, c.RemotePort, shellQuote(c.AgentSocket), c.RemotePort, shellQuote(runtime.GOOS),
		shellQuote(strings.TrimSpace(c.HostKey)), shellQuote(sshCommand), shellQuote(scpCommand), shellQuote(string(connection)), shellQuote(c.AgentHint()), shellQuote(filesvc.ClientScript))
}

const connectionWriter = `import json,os,sys,tempfile
path=os.path.abspath(os.path.expanduser(sys.argv[1]))
data=json.loads(os.environ['ASSH_CONNECTION_JSON'])
sock=os.environ.get('ASSH_AGENT_SOCKET','')
# The snapshot names the socket itself; its readers lack this shell's variables.
data.update(ssh_auth_sock=sock,ssh_command=os.environ.get('ASSH_SSH_COMMAND','').replace('$ASSH_AGENT_SOCKET',sock),socket_ephemeral=True)
if os.path.isdir(path): sys.exit('assh: %s is a directory; give a file path' % path)
if not os.path.isdir(os.path.dirname(path)): sys.exit('assh: directory %s does not exist' % os.path.dirname(path))
fd,tmp=tempfile.mkstemp(prefix='.assh-connection-',dir=os.path.dirname(path))
try:
 with os.fdopen(fd,'w',encoding='utf-8') as f:
  json.dump(data,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 os.chmod(tmp,0o600)
 os.replace(tmp,path)
except BaseException:
 try: os.unlink(tmp)
 except FileNotFoundError: pass
 raise
print(path)
print('assh: saved connection snapshot; the forwarded agent socket expires when this connection closes',file=sys.stderr)`

// AgentHint is printed at the end of the interactive login. It remains
// queryable in the environment for agents which did not observe the welcome.
func (c Config) AgentHint() string {
	return fmt.Sprintf("assh: connected to %s at agent@127.0.0.1:%d\nUse assh help or assh capabilities --json to discover enabled tools.\nassh info --json reports the actual local user and working directory.\nWindows commands use PowerShell. Files: assh put/get/sync; MCP: assh mcp.\nUse assh dry-run before an operation to preview its plan.\n", runtime.GOOS, c.RemotePort)
}

// LoginArgs runs native ssh on the caller's own terminal with the user's
// OpenSSH arguments unchanged, so agent forwarding (-A), port forwards, jump
// hosts and verbosity mean exactly what they mean to ssh. The session command
// starts an interactive Bash whose rcfile is LoginRC, carried compressed
// inside the command. Bash 3 needs a regular rcfile; that temporary file
// deletes itself before profiles or prompts run.
func (c Config) LoginArgs() []string {
	args := append([]string{"-tt"}, remoteCommand(c.LoginCommand())...)
	return append(args, c.SSHArgs...)
}

// loginProfile makes the rcfile behave like a login: sshd shows no MOTD for a
// session that runs a command, so the files pam_motd and sshd read are shown
// here; the profiles then load once, in Bash's login order.
const loginProfile = `# Bash 4+ reads this file from fd 9; close it so the session's commands
# do not inherit it. Bash has read the whole rcfile before running it.
exec 9<&-
for __assh_f in /run/motd.dynamic /etc/motd; do [ -r "$__assh_f" ] && cat "$__assh_f"; done
[ -r /etc/profile ] && . /etc/profile
for __assh_f in ~/.bash_profile ~/.bash_login ~/.profile; do if [ -r "$__assh_f" ]; then . "$__assh_f"; break; fi; done
unset __assh_f
# A non-login shell has no logout builtin and skips ~/.bash_logout.
logout() { exit "$@"; }
[ -n "$(trap -p EXIT)" ] || trap '[ -r ~/.bash_logout ] && . ~/.bash_logout' EXIT
`

// LoginRC is the rcfile of the interactive login Bash.
func (c Config) LoginRC() string {
	return loginProfile + c.RelayShellScript() + "\nprintf '%s' \"$ASSH_AGENT_HELP\"\n"
}

// LoginCommand is the remote command of the interactive login. The relay's
// login shell may be any POSIX sh; Bash itself provides <(...). Without the
// needed tools the user still gets a plain login shell.
func (c Config) LoginCommand() string {
	var b bytes.Buffer
	z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	_, _ = io.WriteString(z, c.LoginRC())
	_ = z.Close()
	payload := base64.StdEncoding.EncodeToString(b.Bytes())
	bootstrap := "__assh_decode() { printf %s " + payload + " | base64 -d | gzip -dc; }; " + `
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  umask 077
  rc=$(mktemp "${TMPDIR:-/tmp}/assh-rc.XXXXXXXX") || exit 1
  trap 'command rm -f -- "$rc"' EXIT HUP INT TERM
  { printf 'command rm -f -- %q\n' "$rc"; __assh_decode; } >"$rc" || exit 1
  exec bash --rcfile "$rc" -i
else
  exec 9< <(__assh_decode)
  exec bash --rcfile /dev/fd/9 -i
fi`
	return "command -v bash >/dev/null && command -v base64 >/dev/null && command -v gzip >/dev/null || " +
		"{ echo 'assh: the relay needs bash, base64 and gzip for the assh environment; starting a plain shell' >&2; exec \"${SHELL:-/bin/sh}\" -l; }; " +
		"exec bash -c " + shellQuote(bootstrap)
}

// RelayCommand is useful to a process outside the interactive SSH session: it
// supplies that tunnel's agent socket and host verification entirely in argv.
func RelayCommand(port int, hostKey, socket string) string {
	return "SSH_AUTH_SOCK=" + shellQuote(socket) + " ssh " + quotedArgs(ReverseOptions(port, hostKey)) + fmt.Sprintf(" -p %d agent@127.0.0.1", port)
}
