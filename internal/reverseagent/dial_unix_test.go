//go:build !windows

package reverseagent

import "net"

func dial(endpoint string) (net.Conn, error) { return net.Dial("unix", endpoint) }
