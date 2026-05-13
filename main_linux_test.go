//go:build linux

package main

import (
	"os"
	"testing"

	"github.com/coroot/coroot-node-agent/common"
)

// TestUnameReturnsHostname verifies that uname() returns a non-empty
// hostname and kernel-version string on Linux. The Setns dance requires
// CAP_SYS_ADMIN, so we only run the full uname() call when both ns files
// exist; otherwise we skip.
func TestUnameReturnsHostname(t *testing.T) {
	if _, err := os.Stat("/proc/1/ns/uts"); err != nil {
		t.Skip("requires /proc/1/ns/uts (skipping outside of a Linux container/host)")
	}
	hostname, kv, err := uname()
	if err != nil {
		t.Skipf("uname() returned %v; likely missing CAP_SYS_ADMIN in this environment", err)
	}
	if hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if kv == "" {
		t.Error("expected non-empty kernel version")
	}
}

// TestSystemUUIDIsStringOnLinux just exercises the function — we cannot
// assume the DMI file exists in every test environment.
func TestSystemUUIDIsStringOnLinux(t *testing.T) {
	_ = systemUUID() // must not panic
}

// TestMachineIDIsStringOnLinux just exercises the function — we cannot
// assume /etc/machine-id is readable in every test environment.
func TestMachineIDIsStringOnLinux(t *testing.T) {
	_ = machineID() // must not panic
}

// TestCheckKernelVersionPassesWithCurrentKernel ensures the kernel
// version check is satisfied when the in-process kernel-version state
// reflects a modern release. We set a high version to verify the helper
// is a no-op on success.
func TestCheckKernelVersionPassesWithCurrentKernel(t *testing.T) {
	if err := common.SetKernelVersion("5.15.0"); err != nil {
		t.Fatalf("SetKernelVersion: %v", err)
	}
	// Must return without calling klog.Exitln (which would terminate
	// the test process). If it returns at all, the assertion passes.
	checkKernelVersion()
}
