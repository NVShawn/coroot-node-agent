//go:build windows

package main

import (
	"os"
	"regexp"
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

// systemUUIDRegex matches the canonical 8-4-4-4-12 hex UUID format that
// Win32_ComputerSystemProduct.UUID returns. The match is case-insensitive
// because Windows reports UUIDs in upper-case while DMI tools historically
// emitted lower-case; we accept either.
var systemUUIDRegex = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// TestSystemUUIDReturnsValidUUID verifies that systemUUID() returns a
// non-empty value in canonical 8-4-4-4-12 UUID format when the WMI query
// against Win32_ComputerSystemProduct.UUID succeeds.
//
// The all-zero UUID ("00000000-0000-0000-0000-000000000000") is a value
// that some hypervisors or BIOSes report when a real UUID is not
// available. We accept it (the format check is what we care about) and
// only fail if the result is empty or malformed.
func TestSystemUUIDReturnsValidUUID(t *testing.T) {
	id := systemUUID()
	if id == "" {
		t.Fatal("expected non-empty system_uuid from Win32_ComputerSystemProduct")
	}
	if !systemUUIDRegex.MatchString(id) {
		t.Errorf("system_uuid %q does not match UUID format 8-4-4-4-12 hex", id)
	}
}

// TestCheckKernelVersionIsNoOpOnWindows verifies that the kernel
// version gate is a no-op on Windows (Linux-specific eBPF prerequisite
// does not apply).
func TestCheckKernelVersionIsNoOpOnWindows(t *testing.T) {
	// Must return without calling klog.Exitln.
	checkKernelVersion()
}
