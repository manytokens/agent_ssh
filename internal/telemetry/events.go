package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

type Event struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Phase     string    `json:"phase"`
	ErrorCode string    `json:"error_code,omitempty"`
	Error     string    `json:"error,omitempty"`
	Port      int       `json:"port,omitempty"`
}
type Events struct {
	mu     sync.Mutex
	file   *os.File
	queue  chan []byte
	cancel context.CancelFunc
	done   chan struct{}
	seq    uint64
	logger *slog.Logger
}

func NewEvents(parent context.Context, path, webhook string, logger *slog.Logger) (*Events, error) {
	ctx, cancel := context.WithCancel(parent)
	e := &Events{cancel: cancel, queue: make(chan []byte, 64), done: make(chan struct{}), logger: logger}
	if path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			cancel()
			return nil, err
		}
		e.file = f
	}
	go func() {
		defer close(e.done)
		client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		defer client.CloseIdleConnections()
		for {
			select {
			case <-ctx.Done():
				return
			case b := <-e.queue:
				if webhook == "" {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(b))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				r, err := client.Do(req)
				if err == nil {
					io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
					r.Body.Close()
					if r.StatusCode >= 300 {
						logger.Warn("event webhook rejected", "status", r.StatusCode)
					}
				} else if ctx.Err() == nil {
					logger.Warn("event webhook failed", "error", err)
				}
			}
		}
	}()
	return e, nil
}
func (e *Events) Emit(v Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seq++
	v.Time = time.Now().UTC()
	v.ID = fmt.Sprintf("%d-%d-%d", os.Getpid(), v.Time.UnixNano(), e.seq)
	b, _ := json.Marshal(v)
	b = append(b, '\n')
	if e.file != nil {
		if _, err := e.file.Write(b); err != nil {
			e.logger.Warn("event log failed", "error", err)
		}
	}
	select {
	case e.queue <- b:
	default:
		e.logger.Warn("event webhook queue full")
	}
}
func (e *Events) Close() error {
	e.cancel()
	<-e.done
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file != nil {
		return e.file.Close()
	}
	return nil
}
