package reverseagent

import (
	"github.com/Microsoft/go-winio"
	"net"
	"strings"
	"time"
)

func dial(endpoint string) (net.Conn, error) {
	timeout := time.Second
	return winio.DialPipe(strings.ReplaceAll(endpoint, "/", `\`), &timeout)
}
