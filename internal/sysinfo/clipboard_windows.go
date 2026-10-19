package sysinfo

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var openClipboard = user32.NewProc("OpenClipboard")
var closeClipboard = user32.NewProc("CloseClipboard")
var getClipboard = user32.NewProc("GetClipboardData")
var setClipboard = user32.NewProc("SetClipboardData")
var emptyClipboard = user32.NewProc("EmptyClipboard")
var kernel = windows.NewLazySystemDLL("kernel32.dll")
var globalAlloc = kernel.NewProc("GlobalAlloc")
var globalLock = kernel.NewProc("GlobalLock")
var globalUnlock = kernel.NewProc("GlobalUnlock")
var globalFree = kernel.NewProc("GlobalFree")
var globalSize = kernel.NewProc("GlobalSize")
var copyMemory = kernel.NewProc("RtlMoveMemory")

func clipboardOpen(ctx context.Context) error {
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if ok, _, _ := openClipboard.Call(0); ok != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("clipboard is busy")
		case <-tick.C:
		}
	}
}
func clipboardGet(ctx context.Context) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := clipboardOpen(ctx); err != nil {
		return "", err
	}
	defer closeClipboard.Call()
	h, _, err := getClipboard.Call(13)
	if h == 0 {
		return "", err
	}
	n, _, _ := globalSize.Call(h)
	if n > 32<<20 {
		return "", errors.New("clipboard exceeds 16 Mi UTF-16 characters")
	}
	p, _, err := globalLock.Call(h)
	if p == 0 {
		return "", err
	}
	defer globalUnlock.Call(h)
	u := make([]uint16, int(n/2))
	if len(u) > 0 {
		copyMemory.Call(uintptr(unsafe.Pointer(&u[0])), p, uintptr(len(u)*2))
	}
	return windows.UTF16ToString(u), nil
}
func clipboardSet(ctx context.Context, text string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if strings.ContainsRune(text, 0) {
		return errors.New("clipboard text cannot contain NUL")
	}
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	if err := clipboardOpen(ctx); err != nil {
		return err
	}
	defer closeClipboard.Call()
	h, _, err := globalAlloc.Call(2, uintptr(len(u)*2))
	if h == 0 {
		return err
	}
	owned := true
	defer func() {
		if owned {
			globalFree.Call(h)
		}
	}()
	p, _, err := globalLock.Call(h)
	if p == 0 {
		return err
	}
	copyMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)*2))
	globalUnlock.Call(h)
	if ok, _, err := emptyClipboard.Call(); ok == 0 {
		return err
	}
	if v, _, err := setClipboard.Call(13, h); v == 0 {
		return err
	}
	owned = false
	return nil
}
