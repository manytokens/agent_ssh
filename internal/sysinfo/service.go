// Package sysinfo implements OS discovery without parsing interactive shell output.
package sysinfo

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"

	"agent_ssh/internal/execsvc"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

type Service struct {
	WorkDir, Shell string
	AllowClipboard bool
}

func encode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

func Identity() map[string]string {
	i := map[string]string{"os": runtime.GOOS}
	if u, err := user.Current(); err == nil {
		i["username"], i["uid"], i["home"] = u.Username, u.Uid, u.HomeDir
	}
	if h, err := os.Hostname(); err == nil {
		i["hostname"] = h
	}
	return i
}

func (s *Service) Handle(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected info, ps, ports or clip")
	}
	dry := false
	var clean []string
	for _, a := range args {
		if a == "--json" {
			continue
		}
		if a == "--dry-run" {
			dry = true
			continue
		}
		clean = append(clean, a)
	}
	args = clean
	if len(args) == 0 {
		return errors.New("missing operation")
	}
	if dry {
		return encode(out, map[string]any{"dry_run": true, "operation": args, "clipboard_enabled": s.AllowClipboard})
	}
	switch args[0] {
	case "ps", "ports":
		for _, a := range args[1:] {
			if a != "--json" {
				return fmt.Errorf("%s takes no arguments (got %q)", args[0], a)
			}
		}
	}
	switch args[0] {
	case "info":
		return s.info(ctx, out)
	case "ps":
		ps, err := process.ProcessesWithContext(ctx)
		if err != nil {
			return err
		}
		rows := make([]map[string]any, 0, len(ps))
		for _, p := range ps {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			name, _ := p.NameWithContext(ctx)
			line, _ := p.CmdlineWithContext(ctx)
			username, _ := p.UsernameWithContext(ctx)
			rows = append(rows, map[string]any{"pid": p.Pid, "name": name, "command_line": line, "user": username})
		}
		return encode(out, rows)
	case "ports":
		cs, err := net.ConnectionsWithContext(ctx, "inet")
		if err != nil {
			return err
		}
		rows := make([]map[string]any, 0)
		for _, c := range cs {
			if c.Status != "LISTEN" && c.Type != 2 {
				continue
			}
			family, kind := "ipv4", "tcp"
			if c.Family == 23 || c.Family == 10 { // AF_INET6 on Windows, Linux
				family = "ipv6"
			}
			if c.Type == 2 { // SOCK_DGRAM
				kind = "udp"
			}
			rows = append(rows, map[string]any{"pid": c.Pid, "address": c.Laddr.IP, "port": c.Laddr.Port, "family": family, "type": kind, "status": c.Status})
		}
		return encode(out, rows)
	case "clip":
		if !s.AllowClipboard {
			return errors.New("clipboard disabled; start assh with --allow-clipboard")
		}
		if len(args) != 2 {
			return errors.New("usage: assh clip get|set (set reads UTF-8 stdin)")
		}
		if args[1] == "get" {
			text, err := clipboardGet(ctx)
			if err != nil {
				return err
			}
			_, err = io.WriteString(out, text)
			return err
		}
		if args[1] == "set" {
			b, err := io.ReadAll(io.LimitReader(in, 16<<20+1))
			if err != nil {
				return err
			}
			if len(b) > 16<<20 {
				return errors.New("clipboard text exceeds 16 MiB")
			}
			return clipboardSet(ctx, string(b))
		}
		return errors.New("unknown clipboard operation")
	}
	return fmt.Errorf("unknown system operation %q", args[0])
}

func (s *Service) info(ctx context.Context, out io.Writer) error {
	i := Identity()
	tools := map[string]any{}
	for _, name := range []string{"git", "node", "docker", "pwsh", "powershell", "wsl", "bash", "tar"} {
		p, e := exec.LookPath(name)
		if name == "bash" {
			// Report what assh bash runs; on Windows that is never the WSL shim.
			p, e = execsvc.BashPath()
		}
		tools[name] = map[string]any{"available": e == nil, "path": p}
	}
	var volumes []map[string]any
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err == nil {
		for _, p := range parts {
			u, e := disk.UsageWithContext(ctx, p.Mountpoint)
			if e == nil {
				volumes = append(volumes, map[string]any{"path": p.Mountpoint, "total": u.Total, "free": u.Free, "used": u.Used})
			}
		}
	}
	version := ""
	if runtime.GOOS == "windows" {
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		b, _ := PowerShell(c, "$PSVersionTable.PSVersion.ToString()")
		cancel()
		version = strings.TrimSpace(string(b))
	}
	docker := map[string]any{"available": false}
	if p, e := exec.LookPath("docker"); e == nil {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		b, e := exec.CommandContext(c, p, "info", "--format", "{{.ServerVersion}}").Output()
		cancel()
		docker = map[string]any{"available": e == nil, "version": strings.TrimSpace(string(b))}
	}
	return encode(out, map[string]any{"identity": i, "os": runtime.GOOS, "arch": runtime.GOARCH, "cwd": s.WorkDir, "shell": s.Shell, "powershell_version": version, "tools": tools, "docker_engine": docker, "volumes": volumes, "clipboard_enabled": s.AllowClipboard})
}

// PowerShell uses Unicode command transport; returned data remains UTF-8.
func PowerShell(ctx context.Context, text string) ([]byte, error) {
	var shell string
	for _, n := range []string{"pwsh.exe", "powershell.exe"} {
		if p, e := exec.LookPath(n); e == nil {
			shell = p
			break
		}
	}
	if shell == "" {
		return nil, errors.New("PowerShell not found")
	}
	script := "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); " + text
	u := utf16.Encode([]rune(script))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)).Output()
}
