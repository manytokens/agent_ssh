package app

import (
	"flag"
	"io"
	"reflect"
	"testing"
)

func testFlags() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("workdir", "", "")
	fs.Int("remote-port", 0, "")
	fs.Bool("no-shell", false, "")
	fs.Bool("json", false, "")
	return fs
}

// Everything that is not one of assh's own options reaches OpenSSH unchanged
// and in order, wherever it appears; assh does not judge it.
func TestOpenSSHArgumentsPassThrough(t *testing.T) {
	for _, tc := range []struct{ in, own, ssh []string }{
		{[]string{"-J", "jump", "-A", "user@relay", "-L", "8080:localhost:80", "-vvv"}, nil, []string{"-J", "jump", "-A", "user@relay", "-L", "8080:localhost:80", "-vvv"}},
		{[]string{"--workdir", `D:\My Projects`, "-p2022", "relay", "--no-shell", "-oUser=me", "--remote-port=22300"},
			[]string{"--workdir", `D:\My Projects`, "--no-shell", "--remote-port=22300"}, []string{"-p2022", "relay", "-oUser=me"}},
		{[]string{"-json", "relay", "-Z", "--typo", "-o"}, []string{"-json"}, []string{"relay", "-Z", "--typo", "-o"}},
		{[]string{"relay", "--", "--json", "-N"}, nil, []string{"relay", "--", "--json", "-N"}},
		{[]string{"-h"}, []string{"-h"}, nil},
	} {
		own, ssh, err := splitArgs(testFlags(), tc.in)
		if err != nil || !reflect.DeepEqual(own, tc.own) || !reflect.DeepEqual(ssh, tc.ssh) {
			t.Errorf("%v: own=%q ssh=%q err=%v", tc.in, own, ssh, err)
		}
	}
}

func TestOwnOptionValuesAndErrors(t *testing.T) {
	fs := testFlags()
	own, ssh, err := splitArgs(fs, []string{"host", "--workdir", "-not-a-flag", "--json"})
	if err != nil || fs.Parse(own) != nil || fs.Lookup("workdir").Value.String() != "-not-a-flag" || !reflect.DeepEqual(ssh, []string{"host"}) {
		t.Fatalf("own=%q ssh=%q err=%v", own, ssh, err)
	}
	if _, _, err := splitArgs(testFlags(), []string{"host", "--workdir"}); err == nil {
		t.Fatal("accepted --workdir without a value")
	}
}
