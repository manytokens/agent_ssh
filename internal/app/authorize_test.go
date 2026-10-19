package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"agent_ssh/internal/state"
	"golang.org/x/crypto/ssh"
)

func TestAuthorizeDefaultsToOpenSSHAndImportsIdempotently(t *testing.T) {
	home, profile := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var out bytes.Buffer
	previous := consoleOutput
	consoleOutput = &out
	t.Cleanup(func() { consoleOutput = previous })
	args := []string{"authorize", "--state-dir", profile}
	if err := Main(args); err == nil {
		t.Fatal("missing OpenSSH file was accepted")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(sshDir, "authorized_keys")
	line := ssh.MarshalAuthorizedKey(key)
	if err := os.WriteFile(source, line, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := Main(args); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(profile, "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := state.ParseKeys(data)
	if err != nil || len(keys) != 1 {
		t.Fatalf("duplicate import: %d keys, %v", len(keys), err)
	}
	if !bytes.Contains(out.Bytes(), []byte(source)) {
		t.Fatalf("source was not reported: %s", out.String())
	}
	// The source belongs to OpenSSH and must remain unchanged.
	data, err = os.ReadFile(source)
	if err != nil || !bytes.Equal(data, line) {
		t.Fatal("modified user's OpenSSH file", err)
	}
}
