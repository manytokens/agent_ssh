package platform

import (
	"bytes"
	"io"
)

// Windows virtual terminals may advance LF without returning to column zero.
// Only console output is wrapped; redirected JSON, logs and SSH streams retain
// their original bytes. Existing CRLF sequences must not become CRCRLF.
type consoleNewlines struct{ out io.Writer }

func (w consoleNewlines) Write(p []byte) (int, error) {
	converted := bytes.ReplaceAll(bytes.ReplaceAll(p, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	n, err := w.out.Write(converted)
	if err != nil {
		return 0, err
	}
	if n != len(converted) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
