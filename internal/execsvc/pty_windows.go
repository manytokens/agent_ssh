//go:build windows

package execsvc

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"agent_ssh/internal/platform"
	"golang.org/x/sys/windows"
)

// Own the ConPTY lifetime here: the upstream winpty backend frees its console
// asynchronously, making concurrent resize unsafe. This backend locks both.
type windowsTerminal struct {
	input, output       *os.File
	console             windows.Handle
	process             windows.Handle
	job                 windows.Handle
	mu                  sync.Mutex
	closeOnce, killOnce sync.Once
}

func (t *windowsTerminal) Read(b []byte) (int, error)  { return t.output.Read(b) }
func (t *windowsTerminal) Write(b []byte) (int, error) { return t.input.Write(b) }
func (t *windowsTerminal) Resize(z Size) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.console == 0 {
		return io.ErrClosedPipe
	}
	if z.Cols == 0 || z.Rows == 0 {
		return fmt.Errorf("terminal size must be positive")
	}
	return windows.ResizePseudoConsole(t.console, windows.Coord{X: int16(z.Cols), Y: int16(z.Rows)})
}
func (t *windowsTerminal) Kill() {
	t.killOnce.Do(func() { platform.KillTree(t.process); windows.TerminateJobObject(t.job, 1); t.input.Close() })
}
func (t *windowsTerminal) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		if t.console != 0 {
			windows.ClosePseudoConsole(t.console)
			t.console = 0
		}
		t.mu.Unlock()
		t.input.Close()
		t.output.Close()
		windows.CloseHandle(t.process)
		windows.CloseHandle(t.job)
	})
	return nil
}
func (t *windowsTerminal) Wait() (int, error) {
	_, err := windows.WaitForSingleObject(t.process, windows.INFINITE)
	var n uint32
	if err == nil {
		err = windows.GetExitCodeProcess(t.process, &n)
	}
	t.mu.Lock()
	if t.console != 0 {
		windows.ClosePseudoConsole(t.console)
		t.console = 0
	}
	t.mu.Unlock()
	return int(n), err
}

func startTerminal(cmd *exec.Cmd, size Size) (terminal, error) {
	t := &windowsTerminal{}
	var inRead, inWrite, outRead, outWrite windows.Handle
	if e := windows.CreatePipe(&inRead, &inWrite, nil, 0); e != nil {
		return nil, e
	}
	if e := windows.CreatePipe(&outRead, &outWrite, nil, 0); e != nil {
		windows.CloseHandle(inRead)
		windows.CloseHandle(inWrite)
		return nil, e
	}
	t.input = os.NewFile(uintptr(inWrite), "conpty-input")
	t.output = os.NewFile(uintptr(outRead), "conpty-output")
	defer windows.CloseHandle(inRead)
	defer windows.CloseHandle(outWrite)
	fail := func(e error) (terminal, error) { t.Close(); return nil, e }
	if e := windows.CreatePseudoConsole(windows.Coord{X: int16(size.Cols), Y: int16(size.Rows)}, inRead, outWrite, 0, &t.console); e != nil {
		return fail(fmt.Errorf("ConPTY unavailable (Windows 10 1809+ required): %w", e))
	}
	var e error
	t.job, e = windows.CreateJobObject(nil, nil)
	if e != nil {
		return fail(e)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, e = windows.SetInformationJobObject(t.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); e != nil {
		return fail(e)
	}
	attrs, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		return fail(e)
	}
	defer attrs.Delete()
	// PSEUDOCONSOLE expects the handle value, not the address of the handle.
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	if ok, _, callErr := update.Call(uintptr(unsafe.Pointer(attrs.List())), 0, 0x00020016, uintptr(t.console), unsafe.Sizeof(t.console), 0, 0); ok == 0 {
		return fail(fmt.Errorf("UpdateProcThreadAttribute(PSEUDOCONSOLE): %w", callErr))
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.ProcThreadAttributeList = attrs.List()
	pi := windows.ProcessInformation{}
	path, e := windows.UTF16PtrFromString(cmd.Path)
	if e != nil {
		return fail(e)
	}
	parts := make([]string, len(cmd.Args))
	for i, a := range cmd.Args {
		parts[i] = windows.EscapeArg(a)
	}
	line, e := windows.UTF16PtrFromString(strings.Join(parts, " "))
	if e != nil {
		return fail(e)
	}
	var dir *uint16
	if cmd.Dir != "" {
		dir, e = windows.UTF16PtrFromString(cmd.Dir)
		if e != nil {
			return fail(e)
		}
	}
	var env *uint16
	var envData []uint16
	if cmd.Env != nil {
		envData = utf16.Encode([]rune(strings.Join(cmd.Env, "\x00") + "\x00\x00"))
		env = &envData[0]
	}
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED)
	if e = windows.CreateProcess(path, line, nil, nil, false, flags, env, dir, &si.StartupInfo, &pi); e != nil {
		return fail(e)
	}
	t.process = pi.Process
	defer windows.CloseHandle(pi.Thread)
	if e = windows.AssignProcessToJobObject(t.job, t.process); e != nil {
		windows.TerminateProcess(t.process, 1)
		return fail(e)
	}
	if _, e = windows.ResumeThread(pi.Thread); e != nil {
		windows.TerminateProcess(t.process, 1)
		return fail(e)
	}
	return t, nil
}
