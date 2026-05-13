//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"k8s.io/klog/v2"
)

// uname returns the hostname and OS version on Windows.
//
// The hostname comes from os.Hostname(). The OS version is derived from
// RtlGetVersion (which, unlike the Win32 GetVersionEx API, is not subject
// to application-compatibility shimming) and is formatted as
// "<MajorVersion>.<MinorVersion>.<BuildNumber>" — a form that
// common.VersionFromString accepts.
func uname() (string, string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", "", err
	}
	info := windows.RtlGetVersion()
	osVersion := fmt.Sprintf("%d.%d.%d", info.MajorVersion, info.MinorVersion, info.BuildNumber)
	return hostname, osVersion, nil
}

// machineID returns a stable per-machine identifier on Windows.
//
// It is read from HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid, a REG_SZ
// value set by Windows at installation time. The hyphens are stripped to
// match the Linux machineID() convention.
//
// A non-empty value is essential: the result is used as a Prometheus label
// (machine_id="..."), and an empty label value collapses series from
// different hosts into one.
func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		klog.Warningln("failed to open registry key for machine-id:", err)
		return ""
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		klog.Warningln("failed to read MachineGuid:", err)
		return ""
	}
	id := strings.TrimSpace(strings.Replace(guid, "-", "", -1))
	klog.Infoln("machine-id: ", id)
	return id
}

// systemUUID returns the system UUID on Windows.
//
// On Linux this is read from /sys/devices/virtual/dmi/id/product_uuid; the
// Windows equivalent lives in Win32_ComputerSystemProduct.UUID and requires
// a WMI client. Full WMI integration is deferred to a follow-up bead — see
// the issue's --notes for the linked tracking bead. Returning an empty
// string here is consistent with the Linux behavior when the DMI file
// cannot be read (the Linux helper returns "" on error too).
func systemUUID() string {
	return ""
}

// checkKernelVersion is a no-op on Windows.
//
// The Linux version of this helper exits if the running kernel is older
// than 4.16, which is a Linux-specific eBPF prerequisite. Windows uses a
// different tracing stack (eBPF-for-Windows / ETW) and has no equivalent
// hard floor at this layer, so this function deliberately does nothing.
func checkKernelVersion() {
}
