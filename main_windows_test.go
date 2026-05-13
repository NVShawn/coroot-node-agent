//go:build windows

package main

import (
	"os"
	"strings"
	"testing"
)

// TestUnameReturnsHostnameAndVersion verifies that on Windows uname()
// returns the OS hostname and a "<major>.<minor>.<build>" formatted
// version string.
func TestUnameReturnsHostnameAndVersion(t *testing.T) {
	hostname, kv, err := uname()
	if err != nil {
		t.Fatalf("uname returned error: %v", err)
	}
	wantHostname, _ := os.Hostname()
	if hostname == "" || hostname != wantHostname {
		t.Errorf("expected hostname=%q, got %q", wantHostname, hostname)
	}
	if kv == "" {
		t.Error("expected non-empty OS version")
	}
	if strings.Count(kv, ".") < 2 {
		t.Errorf("expected version with at least two dots (major.minor.build), got %q", kv)
	}
}

// TestMachineIDIsNonEmptyOnWindows verifies that machineID() returns a
// non-empty identifier on Windows by reading the registry MachineGuid.
// An empty value is unacceptable because the result is used as a
// Prometheus label.
func TestMachineIDIsNonEmptyOnWindows(t *testing.T) {
	id := machineID()
	if id == "" {
		t.Error("expected non-empty machine-id on Windows")
	}
	if strings.Contains(id, "-") {
		t.Errorf("expected hyphens to be stripped, got %q", id)
	}
}

// TestSystemUUIDStubOnWindows documents that systemUUID() currently
// returns an empty string on Windows. This test will need updating once
// WMI integration lands (see the follow-up bead referenced in this
// bead's --notes).
func TestSystemUUIDStubOnWindows(t *testing.T) {
	if got := systemUUID(); got != "" {
		t.Errorf("systemUUID() = %q; expected empty stub until WMI integration ships", got)
	}
}

// TestCheckKernelVersionIsNoOpOnWindows verifies that the kernel
// version gate is a no-op on Windows (Linux-specific eBPF prerequisite
// does not apply).
func TestCheckKernelVersionIsNoOpOnWindows(t *testing.T) {
	// Must return without calling klog.Exitln.
	checkKernelVersion()
}
