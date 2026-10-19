package reverseagent

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

func TestEphemeralIdentityAndLifecycle(t *testing.T) {
	s, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := dial(s.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	a := agent.NewClient(c)
	keys, err := a.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("identities: %v %v", keys, err)
	}
	if !bytes.Equal(keys[0].Blob, s.PublicKey.Marshal()) {
		t.Fatal("wrong identity")
	}
	message := []byte("reverse SSH authentication")
	sig, err := a.Sign(s.PublicKey, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PublicKey.Verify(message, sig); err != nil {
		t.Fatal(err)
	}
	if a.RemoveAll() == nil || a.Remove(s.PublicKey) == nil || a.Lock([]byte("test")) == nil {
		t.Fatal("agent allowed mutation")
	}
	if keys, err := a.List(); err != nil || len(keys) != 1 {
		t.Fatal("mutation affected identity", err)
	}
	other, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if bytes.Equal(s.PublicKey.Marshal(), other.PublicKey.Marshal()) {
		t.Fatal("identity reused across runs")
	}
	s.Close()
	if _, err := a.List(); err == nil {
		t.Fatal("closed agent still serves requests")
	}
	if c, err := dial(s.Endpoint); err == nil {
		c.Close()
		t.Fatal("closed endpoint still accepts connections")
	}
}
