package tunnel

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestAgentEnvironmentPreservesOutboundAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows OpenSSH has a system named-pipe agent fallback")
	}
	for _, userAgent := range []string{"", "/tmp/user-agent.sock"} {
		t.Run(userAgent, func(t *testing.T) {
			t.Setenv("SSH_AUTH_SOCK", userAgent)
			c := Config{ForwardAgent: "/tmp/assh-only.sock"}
			want := userAgent
			if want == "" {
				want = c.ForwardAgent
			}
			count := 0
			for _, value := range c.Env() {
				if strings.HasPrefix(value, "SSH_AUTH_SOCK=") {
					count++
					if value != "SSH_AUTH_SOCK="+want {
						t.Fatal(value)
					}
				}
			}
			if count != 1 || os.Getenv("SSH_AUTH_SOCK") != userAgent {
				t.Fatal("agent fallback duplicated or changed the caller's environment")
			}
		})
	}
}
