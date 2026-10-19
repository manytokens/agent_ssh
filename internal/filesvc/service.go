// Package filesvc implements the structured filesystem and transfer protocol.
package filesvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	Workdir string
	writes  writeLocks
}

func New(workdir string) *Service { return &Service{Workdir: workdir} }
func (s *Service) path(p string) string {
	if runtime.GOOS == "windows" {
		p = strings.ReplaceAll(p, `\`, "/")
		if len(p) >= 3 && p[0] == '/' && ((p[1] >= 'a' && p[1] <= 'z') || (p[1] >= 'A' && p[1] <= 'Z')) && p[2] == '/' {
			p = string(p[1]) + ":" + p[2:]
		}
		if len(p) >= 4 && p[0] == '/' && p[2] == ':' {
			p = p[1:]
		}
		// One spelling per drive: /d/x, d:/x and D:/x all report D:\x.
		if len(p) >= 2 && p[1] == ':' && p[0] >= 'a' && p[0] <= 'z' {
			p = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	p = filepath.FromSlash(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.Workdir, p)
	}
	return filepath.Clean(p)
}

type options struct {
	dry, text, tar bool
	fresh          bool
	hash           string
	transferID     string
	offset, size   int64
	block          int
	excludes       []string
	position       []string
}

func parse(args []string) (o options, err error) {
	o.block = 1024 * 1024
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--dry-run":
			o.dry = true
		case "--text":
			o.text = true
		case "--tar":
			o.tar = true
		case "--json":
		case "--sha256", "--offset", "--size", "--block-size", "--exclude", "--transfer-id":
			i++
			if i == len(args) {
				return o, fmt.Errorf("%s requires a value", a)
			}
			v := args[i]
			switch a {
			case "--transfer-id":
				if v == "" || len(v) > 128 {
					return o, errors.New("invalid transfer ID")
				}
				o.transferID = v
			case "--sha256":
				o.hash = v
			case "--exclude":
				o.excludes = append(o.excludes, v)
			case "--block-size":
				o.block, err = strconv.Atoi(v)
			default:
				var n int64
				n, err = strconv.ParseInt(v, 10, 64)
				if a == "--offset" {
					o.offset = n
				} else {
					o.size = n
				}
			}
			if err != nil {
				return o, err
			}
		default:
			if strings.HasPrefix(a, "--") {
				return o, fmt.Errorf("unknown file option %s", a)
			}
			o.position = append(o.position, a)
		}
	}
	if o.offset < 0 || o.size < 0 || o.block < 4096 || o.block > 16*1024*1024 {
		return o, errors.New("invalid offset, size, or block size (4096..16777216)")
	}
	return
}
func emit(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }
func sha(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), e
}

type Entry struct {
	Path      string    `json:"path"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	Modified  time.Time `json:"modified"`
	Directory bool      `json:"directory"`
	SHA256    string    `json:"sha256,omitempty"`
}

func entry(p string, info os.FileInfo) Entry {
	size := info.Size()
	if info.IsDir() {
		// Directory sizes are filesystem-specific (NTFS reports index size).
		size = 0
	}
	return Entry{Path: p, Name: info.Name(), Size: size, Mode: info.Mode().String(), Modified: info.ModTime().UTC(), Directory: info.IsDir()}
}

// regular reports a clear error when p names a directory or a missing file,
// instead of Windows' "Incorrect function." from reading a directory handle.
func regular(p string) error {
	i, e := os.Stat(p)
	if e != nil {
		return e
	}
	if i.IsDir() {
		return fmt.Errorf("%s is a directory (use --tar for directory transfer, or fs ls)", p)
	}
	return nil
}

// writable rejects targets Windows would silently rewrite or misinterpret:
// a colon names an NTFS alternate data stream, trailing dots and spaces are
// stripped (so "x." would overwrite "x"), and device names such as CON
// create files that ordinary tools cannot delete. An existing directory is
// never replaced by a file.
func writable(p string, file bool) error {
	if runtime.GOOS == "windows" {
		rest := strings.TrimPrefix(p, filepath.VolumeName(p))
		for _, part := range strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' || r == '/' }) {
			if part == "." || part == ".." {
				continue
			}
			if strings.ContainsAny(part, `:*?"<>|`) || strings.IndexFunc(part, func(r rune) bool { return r < 32 }) >= 0 {
				return fmt.Errorf("invalid Windows file name %q (reserved character)", part)
			}
			if strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
				return fmt.Errorf("invalid Windows file name %q (Windows strips trailing dots and spaces)", part)
			}
			base := strings.ToUpper(strings.TrimRight(strings.SplitN(part, ".", 2)[0], " "))
			switch base {
			case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
				return fmt.Errorf("invalid Windows file name %q (reserved device name)", part)
			}
		}
	}
	if file {
		if i, e := os.Stat(p); e == nil && i.IsDir() {
			return fmt.Errorf("%s is an existing directory; give the file path inside it", p)
		}
	}
	return nil
}

// Handle only emits JSON for metadata commands. get/tar-get emit binary bytes.
func (s *Service) Handle(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) (resultErr error) {
	if len(args) == 0 {
		return errors.New("expected fs, put, get, sync, or watch")
	}
	cmd := args[0]
	args = args[1:]
	if cmd == "fs" {
		if len(args) == 0 {
			return errors.New("fs requires ls/stat/hash/find/blocks/stage/write/commit")
		}
		cmd = args[0]
		args = args[1:]
	}
	o, e := parse(args)
	if e != nil {
		return e
	}
	p := "."
	if len(o.position) > 0 {
		p = o.position[0]
		// An omitted path means the working directory; an empty one is a mistake.
		if p == "" {
			return errors.New("empty path; omit it for the working directory")
		}
	}
	p = s.path(p)
	if e = ctx.Err(); e != nil {
		return e
	}
	if !o.dry {
		switch cmd {
		case "stage", "write", "commit", "abort":
			if o.transferID == "" {
				return errors.New("chunked uploads require --transfer-id; use one unique ID across stage/write/commit and abort to release it")
			}
		default:
			if o.transferID != "" {
				return errors.New("--transfer-id is only supported by stage/write/commit/abort")
			}
		}
		writePath := p
		mutating := false
		switch cmd {
		case "mkdir", "stage", "write", "commit", "abort", "put", "tar-put":
			mutating = true
		case "sync":
			if len(o.position) != 2 {
				return errors.New("sync requires source and destination")
			}
			writePath, mutating = s.path(o.position[1]), true
		}
		if mutating {
			if cmd == "abort" && o.transferID == "" {
				return errors.New("abort requires --transfer-id")
			}
			release, err := s.reserveWrite(writePath, o.transferID, cmd)
			if err != nil {
				return err
			}
			defer func() { release(resultErr == nil) }()
		}
	}
	switch cmd {
	case "mkdir", "tar-put":
		if e := writable(p, false); e != nil {
			return e
		}
	case "stage", "write", "commit":
		if e := writable(p, true); e != nil {
			return e
		}
	case "put":
		if e := writable(p, !o.tar); e != nil {
			return e
		}
	case "get":
		if !o.tar && !o.dry {
			if e := regular(p); e != nil {
				return e
			}
		}
	case "hash":
		if e := regular(p); e != nil {
			return e
		}
	case "ls", "watch":
		if o.dry {
			break
		}
		if i, e := os.Stat(p); e != nil {
			return e
		} else if !i.IsDir() {
			return fmt.Errorf("%s is not a directory", p)
		}
	}
	switch cmd {
	case "abort":
		return emit(out, map[string]any{"released": true, "path": p, "dry_run": o.dry})
	case "mkdir":
		if !o.dry {
			if e := os.MkdirAll(p, 0755); e != nil {
				return e
			}
		}
		return emit(out, map[string]any{"path": p, "dry_run": o.dry, "operation": "mkdir"})
	case "ls":
		ds, e := os.ReadDir(p)
		if e != nil {
			return e
		}
		result := []Entry{}
		for _, d := range ds {
			i, e := d.Info()
			if e != nil {
				return e
			}
			result = append(result, entry(filepath.Join(p, d.Name()), i))
		}
		return emit(out, result)
	case "stat", "hash":
		i, e := os.Stat(p)
		if e != nil {
			return e
		}
		v := entry(p, i)
		if cmd == "hash" {
			v.SHA256, e = sha(p)
			if e != nil {
				return e
			}
		}
		return emit(out, v)
	case "find":
		result := []Entry{}
		e := filepath.Walk(p, func(q string, i os.FileInfo, e error) error {
			if e != nil {
				return e
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			rel, _ := filepath.Rel(p, q)
			if excluded(filepath.ToSlash(rel), i.IsDir(), o.excludes) {
				return nil
			}
			result = append(result, entry(q, i))
			return nil
		})
		if e != nil {
			return e
		}
		return emit(out, result)
	case "blocks":
		return blocks(p, o.block, out)
	case "stage":
		return stage(p, o, out)
	case "write":
		return writeChunk(p, o, in, out)
	case "commit":
		return commit(p, o, out)
	case "put":
		if o.tar {
			return unpack(ctx, p, o, in, out)
		}
		return put(ctx, p, o, in, out)
	case "get":
		if o.tar {
			return pack(ctx, p, o, out)
		}
		if o.dry {
			return emit(out, map[string]any{"dry_run": true, "operation": "get", "path": p})
		}
		return get(ctx, p, o, out)
	case "tar-put":
		return unpack(ctx, p, o, in, out)
	case "tar-get":
		return pack(ctx, p, o, out)
	case "sync":
		if len(o.position) != 2 {
			return errors.New("sync requires source and destination")
		}
		return s.sync(ctx, p, s.path(o.position[1]), o, out)
	case "watch":
		if o.dry {
			return emit(out, map[string]any{"dry_run": true, "operation": "watch", "path": p, "recursive": true})
		}
		return watch(ctx, p, out)
	default:
		return fmt.Errorf("unknown file operation %q", cmd)
	}
}
