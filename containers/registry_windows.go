//go:build windows

package containers

import (
	"errors"
	"time"

	"github.com/coroot/coroot-node-agent/gpu"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/prometheus/client_golang/prometheus"
)

// ContainerID is the type the Linux build defines in container_linux.go;
// callers outside this package (e.g. profiling) reference it via the
// ProcessInfo field, so a matching definition has to exist on Windows.
type ContainerID string

// ProcessInfo mirrors the Linux struct shape so platform-agnostic code
// in main.go and profiling/ can pass channels of it across the
// containers/profiling boundary. proc.Flags is itself stubbed in
// proc/fs_windows.go if/when needed; for M0, this struct is never
// populated at runtime on Windows.
type ProcessInfo struct {
	Pid         uint32
	ContainerId ContainerID
	StartedAt   time.Time
	Flags       proc.Flags
}

// ProfilingUpdate mirrors the Linux struct so the profiling/ package
// can declare matching channel types on both platforms. The const
// runtime tags (RuntimeJvm/RuntimeGo) are only referenced inside the
// Linux-only profiling implementation so they are not redeclared
// here.
type ProfilingUpdate struct {
	Pid             uint32
	Runtime         string
	AllocBytes      int64
	AllocObjects    int64
	LockContentions int64
	LockTimeNs      int64
}

// Registry is the Windows stub for the Linux container registry. It
// holds no state because nothing on Windows yet discovers, tracks, or
// instruments containers. The real Windows implementation is M1+/M3
// scope.
type Registry struct{}

// NewRegistry mirrors the Linux constructor signature so main.go can
// call it without a build-tagged branch. The four channels are
// accepted but never read; the returned *Registry is non-nil so
// main.go's nil check does not exit on a Windows host.
//
// The returned error is intentionally nil even though no real
// container discovery happens — main.go treats a non-nil error from
// NewRegistry as a fatal startup failure, and we want the agent
// process to keep running on Windows so the /metrics endpoint and
// node-level collectors can still serve data.
func NewRegistry(_ prometheus.Registerer, _ chan<- ProcessInfo, _ chan *ProfilingUpdate, _ chan gpu.ProcessUsageSample) (*Registry, error) {
	return &Registry{}, nil
}

// Close mirrors the Linux teardown method called from main.go during
// graceful shutdown. There is nothing to release on Windows.
func (r *Registry) Close() {}

// ErrNotImplemented is the canonical not-implemented error returned by
// stubbed helpers within the containers package. It is currently
// unused by external callers but kept here for future _windows.go
// siblings that might bail out at runtime (e.g. JVM/dotnet probes).
var ErrNotImplemented = errors.New("containers: not implemented on windows")
