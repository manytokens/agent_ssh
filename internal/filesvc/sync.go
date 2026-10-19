package filesvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ignoreMatch supports ordered gitignore-style *, ?, **, !, anchored paths and
// directory patterns. Explicit excludes are applied after source .gitignore.
func ignoreMatch(pattern, rel string, dir bool) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || strings.HasPrefix(pattern, "#") {
		return false
	}
	pattern = strings.TrimPrefix(pattern, "!")
	anchored := strings.HasPrefix(pattern, "/")
	pattern = strings.TrimPrefix(pattern, "/")
	directory := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	var b strings.Builder
	if anchored || strings.Contains(pattern, "/") {
		b.WriteString("^")
	} else {
		b.WriteString("(^|/)")
	}
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString("(?:.*/)?")
				} else {
					b.WriteString(".*")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			_, n := utf8.DecodeRuneInString(pattern[i:])
			b.WriteString(regexp.QuoteMeta(pattern[i : i+n]))
			i += n - 1
		}
	}
	if directory {
		if dir {
			b.WriteString("($|/)")
		} else {
			b.WriteString("/")
		}
	} else {
		b.WriteString("($|/)")
	}
	ok, _ := regexp.MatchString(b.String(), rel)
	return ok
}
func excluded(rel string, dir bool, patterns []string) bool {
	result := false
	for _, p := range patterns {
		if ignoreMatch(p, rel, dir) {
			result = !strings.HasPrefix(strings.TrimSpace(p), "!")
		}
	}
	return result
}

type syncResult struct {
	DryRun           bool     `json:"dry_run"`
	Files            int      `json:"files"`
	ChangedFiles     int      `json:"changed_files"`
	ChangedBlocks    int      `json:"changed_blocks"`
	TransferredBytes int64    `json:"transferred_bytes"`
	Paths            []string `json:"paths"`
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }

func (s *Service) sync(ctx context.Context, src, dst string, o options, out io.Writer) error {
	sourcePath, err := canonicalPath(src)
	if err != nil {
		return err
	}
	targetPath, err := canonicalPath(dst)
	if err != nil {
		return err
	}
	if inside(sourcePath, targetPath) || inside(targetPath, sourcePath) {
		return errors.New("sync source and destination must not overlap")
	}
	result := syncResult{DryRun: o.dry, Paths: []string{}}
	if data, e := os.ReadFile(filepath.Join(src, ".gitignore")); e == nil {
		o.excludes = append(strings.Split(string(data), "\n"), o.excludes...)
	}
	e := filepath.Walk(src, func(p string, i os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		rel, e := filepath.Rel(src, p)
		if e != nil {
			return e
		}
		if rel == "." {
			if !i.IsDir() {
				return errors.New("sync source must be a directory")
			}
			if !o.dry {
				return os.MkdirAll(dst, 0755)
			}
			return nil
		}
		if excluded(filepath.ToSlash(rel), i.IsDir(), o.excludes) {
			return nil
		}
		target := filepath.Join(dst, rel)
		if i.IsDir() {
			if !o.dry {
				return os.MkdirAll(target, 0755)
			}
			return nil
		}
		if !i.Mode().IsRegular() {
			return errors.New("sync only supports regular files and directories")
		}
		if !o.dry {
			lock, err := destinationLock(target)
			if err != nil {
				return err
			}
			defer lock.Close()
		}
		result.Files++
		source, e := os.Open(p)
		if e != nil {
			return e
		}
		defer source.Close()
		var input io.Reader = source
		size := i.Size()
		if o.text {
			counter := &countWriter{}
			if e = copyText(counter, contextReader{ctx, source}); e != nil {
				return e
			}
			size = counter.n
			if _, e = source.Seek(0, io.SeekStart); e != nil {
				return e
			}
			reader, writer := io.Pipe()
			defer reader.Close()
			input = reader
			go func() { writer.CloseWithError(copyText(writer, contextReader{ctx, source})) }()
		}
		existing, err := os.Open(target)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if existing != nil {
			defer existing.Close()
		}
		buf := make([]byte, o.block)
		other := make([]byte, o.block)
		offset := int64(0)
		changed := false
		hash := sha256.New()
		var staged *os.File
		defer func() {
			if staged != nil {
				staged.Close()
			}
		}()
		for {
			n, readErr := io.ReadFull(input, buf)
			if n > 0 {
				hash.Write(buf[:n])
				m := 0
				if existing != nil {
					m, _ = io.ReadFull(existing, other)
				}
				if m != n || !bytes.Equal(buf[:n], other[:m]) {
					if !changed {
						changed = true
						if !o.dry {
							if e := stage(target, options{size: size, block: o.block, fresh: true}, io.Discard); e != nil {
								return e
							}
							staged, e = openSafePart(target+".part", os.O_RDWR)
							if e != nil {
								return e
							}
						}
					}
					result.ChangedBlocks++
					result.TransferredBytes += int64(n)
					if !o.dry {
						if _, e = staged.WriteAt(buf[:n], offset); e != nil {
							return e
						}
					}
				}
				offset += int64(n)
			}
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		if !changed && (existing == nil || func() bool { j, e := existing.Stat(); return e == nil && j.Size() != size }()) {
			changed = true
			if !o.dry {
				if e = stage(target, options{size: size, block: o.block, fresh: true}, io.Discard); e != nil {
					return e
				}
			}
		}
		if changed {
			result.ChangedFiles++
			result.Paths = append(result.Paths, filepath.ToSlash(rel))
			if !o.dry {
				if existing != nil {
					existing.Close()
					existing = nil
				}
				if staged != nil {
					if e = staged.Sync(); e != nil {
						return e
					}
					staged.Close()
					staged = nil
				}
				if e = commit(target, options{hash: hex.EncodeToString(hash.Sum(nil))}, io.Discard); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	return emit(out, result)
}
