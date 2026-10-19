package app

import (
	"flag"
	"fmt"
	"strings"
)

// splitArgs takes assh's own options out of args and returns everything else,
// in its original order, for OpenSSH. assh's options are long names (--name or
// -name, optionally =value); OpenSSH has only single-letter options, so
// nothing OpenSSH accepts is taken and nothing is checked here: OpenSSH reports
// its own errors. "--" passes through and ends assh's options as well.
func splitArgs(fs *flag.FlagSet, args []string) (own, ssh []string, err error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			ssh = append(ssh, args[i:]...)
			break
		}
		name, _, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		f := fs.Lookup(name)
		if !strings.HasPrefix(arg, "-") || len(name) < 2 || f == nil {
			if arg == "-h" || arg == "--help" {
				own = append(own, arg)
				continue
			}
			ssh = append(ssh, arg)
			continue
		}
		own = append(own, arg)
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); inline || ok && b.IsBoolFlag() {
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, fmt.Errorf("option %s requires a value", arg)
		}
		i++
		own = append(own, args[i])
	}
	return own, ssh, nil
}
