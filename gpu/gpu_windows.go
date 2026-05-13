//go:build windows

package gpu

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ProcessUsageSample mirrors the Linux struct shape so the containers
// registry constructor accepts the same channel element type on both
// platforms.
type ProcessUsageSample struct {
	UUID          string
	Pid           uint32
	Timestamp     time.Time
	GPUPercent    uint32
	MemoryPercent uint32
}

// Device mirrors the Linux exported shape. The Windows stub never
// populates any devices.
type Device struct {
	UUID string
	Name string
}

// Collector is a prometheus.Collector implementation that emits no
// metrics on Windows. It mirrors the Linux Collector's exported field
// (ProcessUsageSampleCh) so that main.go can pass that channel
// straight into containers.NewRegistry without a platform-specific
// branch.
type Collector struct {
	ProcessUsageSampleCh chan ProcessUsageSample
}

// NewCollector returns an inert collector with a usable but never-fed
// ProcessUsageSampleCh. main.go expects a non-nil *Collector here so
// the registerer.Register call later in startup does not panic on a
// nil interface. M1+ may replace this with a real Windows GPU probe
// (NVIDIA NVML on Windows, AMD ROCm, etc.).
func NewCollector() (*Collector, error) {
	return &Collector{
		ProcessUsageSampleCh: make(chan ProcessUsageSample, 100),
	}, nil
}

// Describe is a no-op so registering the Collector with prometheus
// neither announces nor exposes any descriptors.
func (c *Collector) Describe(_ chan<- *prometheus.Desc) {}

// Collect is a no-op so the /metrics endpoint emits no GPU samples on
// Windows.
func (c *Collector) Collect(_ chan<- prometheus.Metric) {}

// Close mirrors the Linux teardown hook. Nothing to release here.
func (c *Collector) Close() {}
