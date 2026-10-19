package telemetry

import (
	"net"
	"sync/atomic"
	"time"
)

// Metrics counts bytes at the local SSH TCP boundary, including SSH overhead.
type Metrics struct{ Read, Written atomic.Uint64 }
type Snapshot struct {
	Received    uint64    `json:"received_bytes"`
	Sent        uint64    `json:"sent_bytes"`
	ReceiveRate float64   `json:"receive_bytes_per_second"`
	SendRate    float64   `json:"send_bytes_per_second"`
	RoundTripMS float64   `json:"round_trip_ms,omitempty"`
	ProbeAt     time.Time `json:"probe_at,omitzero"`
}
type listener struct {
	net.Listener
	m *Metrics
}
type conn struct {
	net.Conn
	m *Metrics
}

func Wrap(l net.Listener, m *Metrics) net.Listener {
	if m == nil {
		return l
	}
	return &listener{l, m}
}
func (l *listener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	return &conn{c, l.m}, nil
}
func (c *conn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.m.Read.Add(uint64(n))
	return n, e
}
func (c *conn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.m.Written.Add(uint64(n))
	return n, e
}
