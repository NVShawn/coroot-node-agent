//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/yusufpapurcu/wmi"
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

// win32ComputerSystemProduct is the subset of fields we need from the
// Win32_ComputerSystemProduct WMI class. Field names must match the WMI
// property names exactly — see
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct
type win32ComputerSystemProduct struct {
	UUID string
}

// systemUUID returns the system UUID on Windows.
//
// On Linux this is read from /sys/devices/virtual/dmi/id/product_uuid; the
// Windows equivalent is exposed by WMI via the Win32_ComputerSystemProduct
// class. We query the UUID property and return it (trimmed) on success.
//
// The yusufpapurcu/wmi package handles COM initialization on each Query
// (CoInitializeEx with COINIT_MULTITHREADED + LockOSThread + cleanup), so
// this function is safe to call before signal-handler setup in main().
//
// On any WMI failure — service unavailable, COM init error, query timeout —
// the function logs a warning and returns the empty string. That matches
// the Linux helper's behavior when /sys/devices/virtual/dmi/id/product_uuid
// cannot be read.
func systemUUID() string {
	var dst []win32ComputerSystemProduct
	q := wmi.CreateQuery(&dst, "", "Win32_ComputerSystemProduct")
	if err := wmi.Query(q, &dst); err != nil {
		klog.Warningln("failed to query Win32_ComputerSystemProduct:", err)
		return ""
	}
	if len(dst) == 0 {
		klog.Warningln("Win32_ComputerSystemProduct returned no rows")
		return ""
	}
	return strings.TrimSpace(dst[0].UUID)
}

// checkKernelVersion is a no-op on Windows.
//
// The Linux version of this helper exits if the running kernel is older
// than 4.16, which is a Linux-specific eBPF prerequisite. Windows uses a
// different tracing stack (eBPF-for-Windows / ETW) and has no equivalent
// hard floor at this layer, so this function deliberately does nothing.
func checkKernelVersion() {
}
