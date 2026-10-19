package platform

import (
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// started holds the root process of every command started by Start or
// StartInteractive, until its stop function runs.
var started struct {
	sync.Mutex
	roots map[windows.Handle]struct{}
}

var sessionJob struct {
	sync.Once
	handle windows.Handle
	err    error
}

// OwnSession puts the owner itself in a lifetime job before any children are
// created. Children inherit membership atomically, covering termination in
// the gap between cmd.Start and assignment to a per-command job. Keep the
// handle open until OS process teardown: closing it would also kill the owner.
func OwnSession() error {
	sessionJob.Do(func() {
		job, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			sessionJob.err = err
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
		if err == nil {
			err = windows.AssignProcessToJobObject(job, windows.CurrentProcess())
		}
		if err != nil {
			windows.CloseHandle(job)
			sessionJob.err = err
			return
		}
		sessionJob.handle = job
	})
	return sessionJob.err
}

func ConsoleWriter(f *os.File) io.Writer {
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil {
		return consoleNewlines{out: f}
	}
	return f
}

func Lock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func Detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008 | windows.CREATE_NEW_PROCESS_GROUP}
}

func Prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// Job ownership makes closing a session kill descendants, not only PowerShell.
func Start(cmd *exec.Cmd) (func(), error) {
	Prepare(cmd)
	return StartInteractive(cmd)
}

// StartInteractive preserves the parent's console and process group while
// retaining job ownership, including when the parent is forcibly terminated.
func StartInteractive(cmd *exec.Cmd) (func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
	}
	if err != nil {
		if process != 0 {
			windows.CloseHandle(process)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		return nil, err
	}
	started.Lock()
	if started.roots == nil {
		started.roots = map[windows.Handle]struct{}{}
	}
	started.roots[process] = struct{}{}
	started.Unlock()
	// The retained process handle keeps the root PID from being reused, so the
	// tree walk below cannot adopt an unrelated process after a normal exit.
	return func() {
		started.Lock()
		delete(started.roots, process)
		started.Unlock()
		KillTree(process)
		windows.CloseHandle(job)
		windows.CloseHandle(process)
	}, nil
}

// Tracked lists the live started processes and all their descendants. A
// caller persists it so that a restart after a crash can end processes that
// the job object did not hold (see KillTree).
func Tracked() []Record {
	started.Lock()
	known := map[uint32]windows.Filetime{}
	for h := range started.roots {
		pid, err := windows.GetProcessId(h)
		if c, ok := created(h); err == nil && ok && !exited(h) {
			known[pid] = c
		}
	}
	started.Unlock()
	if len(known) == 0 {
		return nil
	}
	procs := snapshot()
	for grew := true; grew; {
		grew = false
		for _, p := range procs {
			parentCreated, isChild := known[p.ppid]
			if _, seen := known[p.pid]; seen || !isChild {
				continue
			}
			h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
			if err != nil {
				continue
			}
			if c, ok := created(h); ok && !before(c, parentCreated) {
				known[p.pid] = c
				grew = true
			}
			windows.CloseHandle(h)
		}
	}
	records := make([]Record, 0, len(known))
	for pid, c := range known {
		records = append(records, Record{PID: pid, Created: uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime)})
	}
	return records
}

// KillRecorded ends each recorded process that still exists with the same
// creation time, and its descendants. A PID reused by another process has a
// different creation time and is left alone.
func KillRecorded(records []Record) int {
	killed := 0
	for _, r := range records {
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, r.PID)
		if err != nil {
			continue
		}
		if c, ok := created(h); ok && uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) == r.Created && !exited(h) {
			KillTree(h)
			killed++
		}
		windows.CloseHandle(h)
	}
	return killed
}

func exited(h windows.Handle) bool {
	var code uint32
	return windows.GetExitCodeProcess(h, &code) != nil || code != 259 // STILL_ACTIVE
}

// KillTree terminates root and every descendant found through parent PIDs.
// Job membership alone is insufficient: processes started by a packaged
// (Microsoft Store) pwsh.exe are created outside the caller's job object.
// Children are matched only when created after their parent, which rejects
// stale parent PIDs that Windows has since reused.
func KillTree(root windows.Handle) {
	rootPID, err := windows.GetProcessId(root)
	if err != nil {
		return
	}
	rootCreated, ok := created(root)
	if !ok {
		return
	}
	known := map[uint32]windows.Filetime{rootPID: rootCreated}
	_ = windows.TerminateProcess(root, 1)
	// Repeat while new descendants appear; a child may be mid-spawn.
	for round := 0; round < 4; round++ {
		found := false
		for _, p := range snapshot() {
			if _, seen := known[p.pid]; seen {
				continue
			}
			parentCreated, isChild := known[p.ppid]
			if !isChild {
				continue
			}
			h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
			if err != nil {
				continue
			}
			if c, ok := created(h); ok && !before(c, parentCreated) {
				known[p.pid] = c
				found = true
				_ = windows.TerminateProcess(h, 1)
			}
			windows.CloseHandle(h)
		}
		if !found {
			return
		}
	}
}

type processEntry struct{ pid, ppid uint32 }

func snapshot() []processEntry {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var result []processEntry
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		result = append(result, processEntry{e.ProcessID, e.ParentProcessID})
	}
	return result
}

func created(h windows.Handle) (windows.Filetime, bool) {
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) != nil {
		return c, false
	}
	return c, true
}

func before(a, b windows.Filetime) bool {
	return a.HighDateTime < b.HighDateTime || (a.HighDateTime == b.HighDateTime && a.LowDateTime < b.LowDateTime)
}
