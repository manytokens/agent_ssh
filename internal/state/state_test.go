package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestIdentityAndKeyPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	a, _ := HostSigner(dir)
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := HostSigner(dir)
	if ssh.FingerprintSHA256(a.PublicKey()) != ssh.FingerprintSHA256(b.PublicKey()) {
		t.Fatal("host identity changed on restart")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	line := ssh.MarshalAuthorizedKey(key)
	if _, err := ParseKeys(line); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeys(append([]byte("no-port-forwarding "), line...)); err == nil {
		t.Fatal("silently accepted a restriction we cannot enforce")
	}
	if _, err := ParseKeys([]byte("# only comments\n")); err == nil {
		t.Fatal("accepted no keys")
	}
	path := filepath.Join(dir, "status.json")
	for _, value := range []string{"first", "replacement"} {
		if err := WriteJSON(path, value); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := ReadJSON(path, &got); err != nil || got != value {
			t.Fatalf("atomic replacement: %q %v", got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "host_ed25519.pub")); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticPairingDoesNotNeedOpenSSHAuthorization(t *testing.T) {
	home, profile := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := Init(profile); err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	pair := struct {
		PublicKey string `json:"public_key"`
	}{string(ssh.MarshalAuthorizedKey(key))}
	if err := WriteJSON(filepath.Join(profile, "relay_pair.json"), pair); err != nil {
		t.Fatal(err)
	}
	keys, err := AgentKeys(profile)
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Marshal(), key.Marshal()) {
		t.Fatalf("automatic authorization: %v %v", keys, err)
	}
	extra, _, _ := ed25519.GenerateKey(rand.Reader)
	extraKey, _ := ssh.NewPublicKey(extra)
	if err := os.WriteFile(filepath.Join(profile, "authorized_keys"), ssh.MarshalAuthorizedKey(extraKey), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err = AgentKeys(profile)
	if err != nil || len(keys) != 2 {
		t.Fatalf("manual authorization must be additive: %v %v", keys, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh")); !os.IsNotExist(err) {
		t.Fatal("pairing modified local OpenSSH configuration")
	}
}

func TestOpenSSHAuthorizationFallbackAndProfilePrecedence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	profile := t.TempDir()
	if err := Init(profile); err != nil {
		t.Fatal(err)
	}
	if _, err := AgentKeys(profile); err == nil {
		t.Fatal("accepted missing OpenSSH authorization")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := ssh.NewPublicKey(public)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(source, ssh.MarshalAuthorizedKey(key), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err := AgentKeys(profile)
	if err != nil || len(keys) != 1 || string(keys[0].Marshal()) != string(key.Marshal()) {
		t.Fatalf("fallback: %v %v", keys, err)
	}
	if err := os.WriteFile(source, append([]byte("restrict "), ssh.MarshalAuthorizedKey(key)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AgentKeys(profile); err == nil {
		t.Fatal("fallback dropped OpenSSH restrictions")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	profileKey, _ := ssh.NewPublicKey(other)
	if err := os.WriteFile(filepath.Join(profile, "authorized_keys"), ssh.MarshalAuthorizedKey(profileKey), 0600); err != nil {
		t.Fatal(err)
	}
	keys, err = AgentKeys(profile)
	if err != nil || len(keys) != 1 || string(keys[0].Marshal()) != string(profileKey.Marshal()) {
		t.Fatalf("profile precedence: %v %v", keys, err)
	}
}
