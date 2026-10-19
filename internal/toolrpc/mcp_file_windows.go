package toolrpc

import "os"

func prepareMCPFile(f *os.File) (*os.File, func(), error) {
	return f, func() {}, nil
}
