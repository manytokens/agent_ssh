package localssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"agent_ssh/internal/state"
	"github.com/jpillora/sftp"
	"golang.org/x/crypto/ssh"
)

func TestCommandsFilesAndForwarding(t *testing.T) {
	dir, work := t.TempDir(), t.TempDir()
	if err := state.Init(dir); err != nil {
		t.Fatal(err)
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	if err := os.WriteFile(filepath.Join(dir, "authorized_keys"), ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600); err != nil {
		t.Fatal(err)
	}
	shell, err := ResolveShell("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	l, done, err := Start(ctx, dir, shell, work, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("server shutdown hung")
		}
	})
	host, _ := state.HostSigner(dir)
	config := &ssh.ClientConfig{User: "agent", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second}
	client, err := ssh.Dial("tcp", l.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Public-key possession is required, even though the listener is loopback.
	bad := *config
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	bad.Auth = []ssh.AuthMethod{ssh.PublicKeys(otherSigner)}
	if c, err := ssh.Dial("tcp", l.Addr().String(), &bad); err == nil {
		c.Close()
		t.Fatal("unauthorized key accepted")
	}

	run := func(command string) (string, error) {
		t.Helper()
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		done := make(chan struct{})
		timer := time.AfterFunc(15*time.Second, func() {
			select {
			case <-done:
			default:
				session.Close()
			}
		})
		defer timer.Stop()
		defer close(done)
		out, err := session.CombinedOutput(command)
		return string(out), err
	}
	text := "printf '你好 agent'"
	if runtime.GOOS == "windows" {
		text = "[Console]::Write('你好 agent')"
	}
	if out, err := run(text); err != nil || out != "你好 agent" {
		t.Fatalf("UTF-8 output: %q %v", out, err)
	}
	for _, code := range []int{0, 7} {
		text := "exit 0"
		if code == 7 {
			text = "exit 7"
		}
		_, err := run(text)
		if code == 0 && err != nil {
			t.Fatal(err)
		}
		if code == 7 {
			e, ok := err.(*ssh.ExitError)
			if !ok || e.ExitStatus() != 7 {
				t.Fatalf("exit 7: %v", err)
			}
		}
	}
	if runtime.GOOS == "windows" {
		for _, text := range []string{"Write-Error 'expected-error'", "& cmd.exe /d /c 'exit 9'"} {
			if out, err := run(text); err == nil {
				t.Fatalf("failure reported success: %s %q", text, out)
			}
		}
		// Closing an SSH channel must also stop a child spawned by PowerShell.
		childSession, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		childOut, err := childSession.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		script := "$p=Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 60' -PassThru; [Console]::WriteLine($p.Id); Start-Sleep -Seconds 60"
		if err := childSession.Start(script); err != nil {
			t.Fatal(err)
		}
		pidLine := make(chan string, 1)
		go func() {
			reader := bufio.NewReader(childOut)
			line, _ := reader.ReadString('\n')
			pidLine <- strings.TrimSpace(line)
		}()
		var pid string
		select {
		case pid = <-pidLine:
		case <-time.After(10 * time.Second):
			childSession.Close()
			t.Fatal("child process did not start")
		}
		if _, err := strconv.Atoi(pid); err != nil {
			childSession.Close()
			t.Fatalf("invalid child PID: %q", pid)
		}
		childSession.Close()
		deadline := time.Now().Add(5 * time.Second)
		for {
			out, err := run("if (Get-Process -Id " + pid + " -ErrorAction SilentlyContinue) { exit 1 }; [Console]::Write('gone')")
			if err == nil && out == "gone" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("PowerShell child survived session close:", pid, out, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	// Closing stdin must not cancel a command before output is drained.
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	session.Stdin = strings.NewReader("hello stdin\n")
	text = "cat"
	if runtime.GOOS == "windows" {
		text = "[Console]::Write([Console]::In.ReadToEnd())"
	}
	out, err := session.Output(text)
	session.Close()
	if err != nil || !bytes.Contains(out, []byte("hello stdin")) {
		t.Fatalf("stdin: %q %v", out, err)
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer sftpClient.Close()
	payload := append([]byte{0, 255, 0, 128}, bytes.Repeat([]byte("binary\n"), 1024)...)
	f, err := sftpClient.Create("中文 file.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	f.Close()
	f, err = sftpClient.Open("中文 file.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(payload, got) {
		t.Fatalf("SFTP binary mismatch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, "中文 file.bin")); err != nil {
		t.Fatal("SFTP workdir:", err)
	}
	if runtime.GOOS == "windows" {
		// Upstream SFTP takes Windows drives as /C:/... (asscp converts C:/...).
		absolute := filepath.ToSlash(filepath.Join(work, "中文 file.bin"))
		for _, remote := range []string{"/" + absolute, "/" + strings.ToLower(absolute[:1]) + absolute[1:]} {
			f, err := sftpClient.Open(remote)
			if err != nil {
				t.Fatalf("SFTP absolute path %q: %v", remote, err)
			}
			got, err := io.ReadAll(f)
			f.Close()
			if err != nil || !bytes.Equal(payload, got) {
				t.Fatalf("SFTP absolute path content %q: %v", remote, err)
			}
		}
	}

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	c, err := client.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	checkEcho(t, c)
	reverse, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reverse.Close()
	go func() {
		c, err := reverse.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	c, err = net.DialTimeout("tcp", reverse.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	checkEcho(t, c)

	// Cancellation must close active commands and release the server promptly.
	long, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer long.Close()
	text = "sleep 60"
	if runtime.GOOS == "windows" {
		text = "Start-Sleep -Seconds 60"
	}
	if err := long.Start(text); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- long.Wait() }()
	long.Close()
	select {
	case <-finished:
	case <-time.After(8 * time.Second):
		t.Fatal("cancelled exec hung")
	}
}

func checkEcho(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("forward echo: %q %v", b, err)
	}
}
