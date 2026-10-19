// Package toolrpc implements the argv-safe SSH tool transport and MCP stdio bridge.
package toolrpc

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const Prefix = "__assh_rpc_v1 "

// Encode uses NUL-terminated arguments so empty arguments round-trip as well.
func Encode(args []string) string {
	if len(args) == 0 {
		return Prefix
	}
	return Prefix + base64.StdEncoding.EncodeToString([]byte(strings.Join(args, "\x00")+"\x00"))
}

// Decode distinguishes ordinary shell commands from reserved tool invocations.
func Decode(command string) ([]string, bool, error) {
	encoded, ok := strings.CutPrefix(command, Prefix)
	if !ok {
		return nil, false, nil
	}
	if encoded == "" {
		return nil, true, nil
	}
	if len(encoded) > 4*1024*1024 {
		return nil, true, fmt.Errorf("tool arguments exceed 3 MiB")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, true, fmt.Errorf("invalid tool arguments: %w", err)
	}
	if len(data) == 0 || data[len(data)-1] != 0 {
		return nil, true, fmt.Errorf("tool arguments require NUL terminator")
	}
	return strings.Split(string(data[:len(data)-1]), "\x00"), true, nil
}
