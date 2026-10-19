package audit

import (
	"context"
	"time"

	"agent_ssh/internal/toolproto"
)

type connectionKey struct{}
type connection struct {
	log        *Log
	conn, user string
}

// WithConnection carries SSH attribution through nested MCP tool calls.
func WithConnection(ctx context.Context, log *Log, conn, user string) context.Context {
	return context.WithValue(ctx, connectionKey{}, connection{log, conn, user})
}

// Begin records a completed operation. The fallback covers non-SSH callers.
func Begin(ctx context.Context, fallback *Log, args []string) func(error) {
	c, ok := ctx.Value(connectionKey{}).(connection)
	if !ok {
		c.log = fallback
	}
	entry := Entry{Time: time.Now(), Kind: "tool", Conn: c.conn, User: c.user, Args: append([]string(nil), args...)}
	return func(err error) {
		entry.DurationMS = time.Since(entry.Time).Milliseconds()
		entry.ExitCode = Code(toolproto.ExitCode(err))
		if err != nil {
			entry.Error = err.Error()
		}
		c.log.Write(entry)
	}
}
