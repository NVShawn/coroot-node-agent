//go:build windows

package node

import (
	"inet.af/netaddr"
)

// NetDeviceInfo mirrors the Linux struct used by node/collector.go's
// Collect method and by main.go's whitelistNodeExternalNetworks. The
// fields are intentionally identical so that platform-agnostic call
// sites see the same shape on both OSes.
type NetDeviceInfo struct {
	Name       string
	Up         float64
	IPPrefixes []netaddr.IPPrefix
	RxBytes    float64
	TxBytes    float64
	RxPackets  float64
	TxPackets  float64
}

// NetDevices is the Windows stub for the Linux netlink-based interface
// enumerator. Returning an empty slice means Collect emits no
// per-interface metrics and whitelistNodeExternalNetworks discovers no
// external prefixes — both behave as if the host has no NICs. The
// real Windows implementation (using GetAdaptersAddresses or
// equivalent) is M1+ scope.
func NetDevices() ([]NetDeviceInfo, error) {
	return nil, nil
}
