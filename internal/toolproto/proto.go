// Package toolproto is the shared streaming interface for authenticated SSH tools.
package toolproto

import (
	"context"
	"errors"
	"fmt"
	"io"
)

type Handler func(context.Context, []string, io.Reader, io.Writer, io.Writer) error

type Terminal struct {
	Cols, Rows uint32
	Resizes    <-chan []byte
}
type terminalKey struct{}

func WithTerminal(ctx context.Context, t Terminal) context.Context {
	return context.WithValue(ctx, terminalKey{}, t)
}
func TerminalFromContext(ctx context.Context) (Terminal, bool) {
	t, ok := ctx.Value(terminalKey{}).(Terminal)
	return t, ok
}

type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("command exited with status %d", e.Code) }

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var e ExitError
	if errors.As(err, &e) {
		return e.Code
	}
	var p *ExitError
	if errors.As(err, &p) {
		return p.Code
	}
	return 1
}
