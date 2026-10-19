package platform

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ConsoleInput preserves native OpenSSH's real console input handle, including
// its raw input and resize handling. Only the startup commands are enqueued.
func ConsoleInput() (func(string) error, bool) {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return nil, false
	}
	write := windows.NewLazySystemDLL("kernel32.dll").NewProc("WriteConsoleInputW")
	type record struct {
		Kind       uint16
		Padding    uint16
		Down       int32
		Repeat     uint16
		VirtualKey uint16
		Scan       uint16
		Char       uint16
		Control    uint32
	}
	return func(s string) error {
		chars := utf16.Encode([]rune(strings.ReplaceAll(s, "\n", "\r")))
		records := make([]record, len(chars))
		for i, ch := range chars {
			records[i] = record{Kind: 1, Down: 1, Repeat: 1, Char: ch}
			if ch == '\r' {
				records[i].VirtualKey = 13
			}
		}
		for len(records) > 0 {
			var written uint32
			ok, _, err := write.Call(uintptr(h), uintptr(unsafe.Pointer(&records[0])), uintptr(len(records)), uintptr(unsafe.Pointer(&written)))
			if ok == 0 || written == 0 {
				return fmt.Errorf("initialize SSH console input: %w", err)
			}
			records = records[written:]
		}
		return nil
	}, true
}
