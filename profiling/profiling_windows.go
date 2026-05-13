//go:build windows

package profiling

import (
	"time"

	"github.com/coroot/coroot-node-agent/containers"
)

// CollectInterval, SampleRate, and UploadTimeout mirror the constants
// declared on Linux so any platform-agnostic code that references them
// resolves to the same numeric values. None of them are actually used
// at runtime on Windows in M0 because the Init stub never starts a
// session.
const (
	CollectInterval = time.Minute
	SampleRate      = 100
	UploadTimeout   = 10 * time.Second
)

// Init is the Windows stub for the eBPF-backed profiler. It returns:
//   - a nil ProcessInfo channel (no profiler consuming process info),
//   - a usable but never-fed ProfilingUpdate channel so that callers
//     storing the second return value (e.g. containers.NewRegistry)
//     can still send into it without a nil-channel panic.
//
// The real Windows profiling pipeline is M3 scope (ebpfwin/etwtracer
// parallel packages).
func Init(_, _ string) (chan<- containers.ProcessInfo, chan *containers.ProfilingUpdate) {
	updateCh := make(chan *containers.ProfilingUpdate, 100)
	return nil, updateCh
}

// Start is a no-op on Windows because Init never creates a profiling
// session.
func Start() {}

// Stop is a no-op on Windows because there is no profiling session to
// tear down.
func Stop() {}
