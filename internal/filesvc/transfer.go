package filesvc

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func blocks(p string, n int, out io.Writer) error {
	f, e := os.Open(p)
	if os.IsNotExist(e) {
		return emit(out, map[string]any{"exists": false, "size": 0, "block_size": n, "blocks": []string{}})
	}
	if e != nil {
		return e
	}
	defer f.Close()
	return blocksFile(f, n, out)
}
func blocksFile(f *os.File, n int, out io.Writer) error {
	i, e := f.Stat()
	if e != nil {
		return e
	}
	if !i.Mode().IsRegular() {
		return errors.New("blocks requires a regular file")
	}
	hs := []string{}
	buf := make([]byte, n)
	h := sha256.New()
	for {
		nr, e := io.ReadFull(f, buf)
		if nr > 0 {
			b := buf[:nr]
			h.Write(b)
			sum := sha256.Sum256(b)
			hs = append(hs, hex.EncodeToString(sum[:]))
		}
		if e == io.EOF || e == io.ErrUnexpectedEOF {
			break
		}
		if e != nil {
			return e
		}
	}
	return emit(out, map[string]any{"exists": true, "size": i.Size(), "block_size": n, "blocks": hs, "sha256": hex.EncodeToString(h.Sum(nil))})
}
func stage(p string, o options, out io.Writer) error {
	if o.dry {
		return emit(out, map[string]any{"dry_run": true, "operation": "stage", "path": p, "size": o.size})
	}
	if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
		return e
	}
	part := p + ".part"
	// With the source digest, an identical target is left untouched: no copy
	// into .part and no rename, so an unchanged sync rewrites nothing.
	if o.hash != "" {
		if i, e := os.Stat(p); e == nil && i.Mode().IsRegular() && i.Size() == o.size {
			if digest, e := sha(p); e == nil && strings.EqualFold(digest, o.hash) {
				if e := os.Remove(part); e != nil && !os.IsNotExist(e) {
					return e
				}
				return emit(out, map[string]any{"unchanged": true, "exists": true, "size": i.Size(), "sha256": digest})
			}
		}
	}
	if o.fresh {
		if e := os.Remove(part); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	f, e := openSafePart(part, os.O_CREATE|os.O_RDWR|os.O_EXCL)
	if os.IsExist(e) {
		f, e = openSafePart(part, os.O_RDWR)
	} else if e == nil {
		src, err := os.Open(p)
		if err == nil {
			_, err = io.Copy(f, src)
			src.Close()
		}
		if err != nil && !os.IsNotExist(err) {
			f.Close()
			return err
		}
	}
	if e != nil {
		return e
	}
	defer f.Close()
	if e = f.Truncate(o.size); e != nil {
		return e
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	return blocksFile(f, o.block, out)
}
func writeChunk(p string, o options, in io.Reader, out io.Writer) error {
	if o.dry {
		return emit(out, map[string]any{"dry_run": true, "operation": "write", "path": p, "offset": o.offset, "size": o.size})
	}
	if o.hash == "" {
		return errors.New("write requires --sha256")
	}
	data, e := io.ReadAll(io.LimitReader(in, 16*1024*1024+1))
	if e != nil {
		return e
	}
	if len(data) > 16*1024*1024 {
		return errors.New("chunk exceeds 16 MiB")
	}
	if int64(len(data)) != o.size {
		return errors.New("chunk size mismatch")
	}
	h := sha256.Sum256(data)
	if !strings.EqualFold(o.hash, hex.EncodeToString(h[:])) {
		return errors.New("chunk SHA256 mismatch")
	}
	f, e := openSafePart(p+".part", os.O_RDWR)
	if e != nil {
		return e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return e
	}
	if o.offset > i.Size() || o.size > i.Size()-o.offset {
		return errors.New("chunk extends beyond staged file")
	}
	_, e = f.WriteAt(data, o.offset)
	if e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return emit(out, map[string]any{"written": len(data), "offset": o.offset})
}
func commit(p string, o options, out io.Writer) error {
	if o.dry {
		return emit(out, map[string]any{"dry_run": true, "operation": "commit", "path": p})
	}
	if o.hash == "" {
		return errors.New("commit requires --sha256")
	}
	actual, e := commitSafePart(p, o.hash)
	if e != nil {
		return e
	}
	return emit(out, map[string]any{"path": p, "sha256": actual, "committed": true})
}
func normalizeText(data []byte) []byte { return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")) }
func put(ctx context.Context, p string, o options, in io.Reader, out io.Writer) error {
	if o.dry {
		return emit(out, map[string]any{"dry_run": true, "operation": "put", "path": p})
	}
	if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
		return e
	}
	f, e := openSafePart(p+".part", os.O_CREATE|os.O_WRONLY)
	if e != nil {
		return e
	}
	if e = f.Truncate(0); e != nil {
		f.Close()
		return e
	}
	h := sha256.New()
	writer := io.MultiWriter(f, h)
	r := io.Reader(contextReader{ctx, in})
	if o.text {
		e = copyText(writer, r)
	} else {
		_, e = io.Copy(writer, r)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if o.hash != "" && !strings.EqualFold(actual, o.hash) {
		return errors.New("file SHA256 mismatch; .part retained")
	}
	o.hash = actual
	return commit(p, o, out)
}
func copyText(out io.Writer, in io.Reader) error {
	// Streaming CRLF to LF conversion; standalone CR and UTF-8 bytes are preserved.
	buf := make([]byte, 64*1024)
	pending := false
	for {
		n, e := in.Read(buf)
		data := buf[:n]
		if pending {
			data = append([]byte{'\r'}, data...)
			pending = false
		}
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
			pending = true
		}
		if len(data) > 0 {
			if _, err := out.Write(normalizeText(data)); err != nil {
				return err
			}
		}
		if e != nil {
			if e != io.EOF {
				return e
			}
			if pending {
				_, e = out.Write([]byte{'\r'})
				return e
			}
			return nil
		}
	}
}
func get(ctx context.Context, p string, o options, out io.Writer) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	if o.offset > 0 {
		if _, e = f.Seek(o.offset, io.SeekStart); e != nil {
			return e
		}
	}
	r := io.Reader(contextReader{ctx, f})
	if o.size > 0 {
		r = io.LimitReader(r, o.size)
	}
	if o.text {
		return copyText(out, r)
	}
	_, e = io.Copy(out, r)
	return e
}
func pack(ctx context.Context, p string, o options, out io.Writer) error {
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("tar source %s is not a directory; omit --tar for a file", p)
	}
	if o.dry {
		return emit(out, map[string]any{"dry_run": true, "operation": "tar-get", "path": p})
	}
	tw := tar.NewWriter(out)
	e := filepath.Walk(p, func(q string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		rel, e := filepath.Rel(p, q)
		if e != nil {
			return e
		}
		if rel == "." {
			return nil
		}
		if excluded(filepath.ToSlash(rel), i.IsDir(), o.excludes) {
			return nil
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("tar does not follow symlink %s", q)
		}
		h, e := tar.FileInfoHeader(i, "")
		if e != nil {
			return e
		}
		h.Name = filepath.ToSlash(rel)
		if i.Mode().IsRegular() {
			digest, err := sha(q)
			if err != nil {
				return err
			}
			h.PAXRecords = map[string]string{"ASSH.sha256": digest}
			h.Format = tar.FormatPAX
		}
		if e = tw.WriteHeader(h); e != nil {
			return e
		}
		if !i.Mode().IsRegular() {
			return nil
		}
		f, e := os.Open(q)
		if e != nil {
			return e
		}
		_, e = io.Copy(tw, contextReader{ctx, f})
		f.Close()
		return e
	})
	ce := tw.Close()
	if e != nil {
		return e
	}
	return ce
}
func unpack(ctx context.Context, p string, o options, in io.Reader, out io.Writer) error {
	if o.dry {
		return emit(out, map[string]any{"dry_run": true, "operation": "tar-put", "path": p})
	}
	// The root exists even when the archive is empty (an empty source directory).
	if e := os.MkdirAll(p, 0755); e != nil {
		return e
	}
	tr := tar.NewReader(contextReader{ctx, in})
	count, dirs := 0, 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		name := filepath.FromSlash(h.Name)
		if filepath.IsAbs(name) || filepath.VolumeName(name) != "" || name == ".." || strings.HasPrefix(filepath.Clean(name), ".."+string(filepath.Separator)) {
			return errors.New("unsafe tar member")
		}
		q := filepath.Join(p, name)
		if e := writable(q, h.Typeflag != tar.TypeDir); e != nil {
			return e
		}
		// Archive entries never follow symlink directories, independently of shell access.
		for parent := filepath.Dir(q); ; parent = filepath.Dir(parent) {
			if i, e := os.Lstat(parent); e == nil && i.Mode()&os.ModeSymlink != 0 {
				return errors.New("tar member traverses symlink")
			}
			if parent == p || parent == filepath.Dir(parent) {
				break
			}
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if !o.dry {
				if e = os.MkdirAll(q, 0755); e != nil {
					return e
				}
			}
			dirs++
			continue
		case tar.TypeReg, tar.TypeRegA:
			if !o.dry {
				lock, err := destinationLock(q)
				if err != nil {
					return err
				}
				e = put(ctx, q, options{hash: h.PAXRecords["ASSH.sha256"]}, tr, io.Discard)
				lock.Close()
				if e != nil {
					return e
				}
			}
		default:
			return fmt.Errorf("unsupported tar member type %d", h.Typeflag)
		}
		count++
	}
	// tar.Reader stops at the end markers, before optional record padding.
	// Consume the rest of stdin before closing the channel so a streaming
	// uploader can finish writing its archive without a broken pipe.
	if _, err := io.Copy(io.Discard, contextReader{ctx, in}); err != nil {
		return err
	}
	return emit(out, map[string]any{"path": p, "files": count, "directories": dirs, "dry_run": o.dry})
}
