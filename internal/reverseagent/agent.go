// Package reverseagent serves a dedicated, memory-only SSH signing identity.
package reverseagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Server struct {
	Endpoint    string
	PublicKey   ssh.PublicKey
	listener    net.Listener
	cleanup     func()
	once        sync.Once
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	closed      bool
	wg          sync.WaitGroup
}

func Start() (*Server, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: private, Comment: "assh ephemeral reverse access"}); err != nil {
		return nil, err
	}
	l, endpoint, cleanup, err := listen()
	if err != nil {
		return nil, err
	}
	s := &Server{Endpoint: endpoint, PublicKey: key, listener: l, cleanup: cleanup, connections: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.connections[conn] = struct{}{}
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer conn.Close()
				defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
				_ = agent.ServeAgent(readOnly{keyring}, conn)
			}()
		}
	}()
	return s, nil
}

func (s *Server) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		for conn := range s.connections {
			conn.Close()
		}
		s.mu.Unlock()
		s.listener.Close()
		s.wg.Wait()
		s.cleanup()
	})
	return nil
}

type readOnly struct{ agent.Agent }

var errReadOnly = errors.New("assh agent is read-only")

func (readOnly) Add(agent.AddedKey) error   { return errReadOnly }
func (readOnly) Remove(ssh.PublicKey) error { return errReadOnly }
func (readOnly) RemoveAll() error           { return errReadOnly }
func (readOnly) Lock([]byte) error          { return errReadOnly }
func (readOnly) Unlock([]byte) error        { return errReadOnly }
