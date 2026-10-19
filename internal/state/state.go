// Package state owns persistent device identity and per-profile runtime files.
package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func DefaultDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent_ssh"), nil
}

func Token() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// WriteJSON uses an atomic replacement so readers never observe partial state.
func WriteJSON(path string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".assh-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(append(b, '\n'))
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func ReadJSON(path string, value any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}

func Init(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// A process-level lock must be held by callers mutating this directory.
	keyPath := filepath.Join(dir, "host_ed25519")
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		block, err := ssh.MarshalPrivateKey(private, "agent_ssh device host key")
		if err != nil {
			return err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	signer, err := HostSigner(dir)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "authorized_keys"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

func HostSigner(dir string) (ssh.Signer, error) {
	b, err := os.ReadFile(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func OpenSSHAuthorizedKeysPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

// AgentKeys accepts the automatically paired relay key plus explicit profile
// keys. The OpenSSH fallback is only used when neither is available.
func AgentKeys(dir string) ([]ssh.PublicKey, error) {
	var pair struct {
		PublicKey string `json:"public_key"`
	}
	paired := false
	if err := ReadJSON(filepath.Join(dir, "relay_pair.json"), &pair); err == nil {
		paired = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var pairedKeys []ssh.PublicKey
	if paired {
		var err error
		pairedKeys, err = ParseKeys([]byte(pair.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("relay pairing: %w", err)
		}
	}
	path := filepath.Join(dir, "authorized_keys")
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys, err := ParseKeys(data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			return append(pairedKeys, keys...), nil
		}
	}
	if paired {
		return pairedKeys, nil
	}
	path, err = OpenSSHAuthorizedKeysPath()
	if err != nil {
		return nil, err
	}
	data, err = ReadOpenSSHAuthorizedKeys(path)
	if err != nil {
		return nil, err
	}
	keys, err := ParseKeys(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return keys, nil
}

func ReadOpenSSHAuthorizedKeys(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("OpenSSH authorized_keys not found: %s; use 'assh authorize <agent-public-key-file>' to authorize an agent (id_ed25519.pub is an outbound identity, not an inbound authorization list)", path)
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ParseKeys deliberately rejects OpenSSH options rather than silently dropping
// restrictions such as command= or no-port-forwarding.
func ParseKeys(data []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("invalid public key on line %d", i+1)
		}
		if len(options) > 0 {
			return nil, fmt.Errorf("authorized_keys options on line %d are not supported; use a dedicated plain agent public key", i+1)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("no agent public keys: run 'assh authorize <public-key-file>' first")
	}
	return keys, nil
}
