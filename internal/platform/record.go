package platform

// Record identifies a process across PID reuse by its creation time (a
// Windows FILETIME).
type Record struct {
	PID     uint32 `json:"pid"`
	Created uint64 `json:"created"`
}
