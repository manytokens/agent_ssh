package reverseagent

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func listen() (net.Listener, string, func(), error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, "", nil, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, "", nil, err
	}
	path := `\\.\pipe\assh-agent-` + hex.EncodeToString(random[:])
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + user.User.Sid.String() + ")"})
	// OpenSSH's config expansion doubles backslashes. Its Win32 pipe layer
	// accepts slash separators, which also survive its initial stat check.
	return l, strings.ReplaceAll(path, `\`, "/"), func() {}, err
}
