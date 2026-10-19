package filesvc

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

func watch(ctx context.Context, p string, out io.Writer) error {
	w, e := fsnotify.NewWatcher()
	if e != nil {
		return e
	}
	defer w.Close()
	add := func(root string) error {
		return filepath.Walk(root, func(q string, i os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			if i.IsDir() {
				return w.Add(q)
			}
			return nil
		})
	}
	if e = add(p); e != nil {
		return e
	}
	if e = emit(out, map[string]any{"event": "ready", "path": p, "recursive": true}); e != nil {
		return e
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-w.Errors:
			if !ok {
				return nil
			}
			if e = emit(out, map[string]any{"event": "error", "error": e.Error(), "rescan_required": true}); e != nil {
				return e
			}
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if ev.Op&fsnotify.Create != 0 {
				if i, e := os.Stat(ev.Name); e == nil && i.IsDir() {
					if e = add(ev.Name); e != nil {
						if e = emit(out, map[string]any{"event": "error", "error": e.Error(), "rescan_required": true}); e != nil {
							return e
						}
					}
				}
			}
			if e = emit(out, map[string]any{"event": ev.Op.String(), "path": ev.Name, "time": time.Now().UTC()}); e != nil {
				return e
			}
		}
	}
}
