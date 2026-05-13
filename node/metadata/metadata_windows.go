//go:build windows

package metadata

// CloudProvider is the type used by node/collector.go to describe which
// cloud the host runs in. The set of constants below mirrors the Linux
// build so platform-agnostic code can switch on the same identifiers.
type CloudProvider string

const (
	CloudProviderAWS          CloudProvider = "AWS"
	CloudProviderGCP          CloudProvider = "GCP"
	CloudProviderAzure        CloudProvider = "Azure"
	CloudProviderHetzner      CloudProvider = "Hetzner"
	CloudProviderDigitalOcean CloudProvider = "DigitalOcean"
	CloudProviderAlibaba      CloudProvider = "Alibaba"
	CloudProviderScaleway     CloudProvider = "Scaleway"
	CloudProviderIBM          CloudProvider = "IBM"
	CloudProviderOracle       CloudProvider = "Oracle"
	CloudProviderUnknown      CloudProvider = ""
)

// CloudMetadata mirrors the Linux struct shape so node/collector.go's
// embedding (instanceMetadata *metadata.CloudMetadata) compiles and so
// any prometheus labels derived from it default to empty strings on
// Windows. M1+ will replace this stub with real cloud-provider
// detection on Windows.
type CloudMetadata struct {
	Provider           CloudProvider
	AccountId          string
	InstanceId         string
	InstanceType       string
	LifeCycle          string
	Region             string
	AvailabilityZone   string
	AvailabilityZoneId string
	LocalIPv4          string
	PublicIPv4         string
}

// GetInstanceMetadata is the Windows stub for the Linux cloud-provider
// dispatcher. Cloud-detection on Windows reads from different sources
// (the Windows registry, Hyper-V WMI properties, etc.) and is M1+
// scope. For now we return nil so node/collector.go falls back to its
// empty-CloudMetadata default and flag-overrides path.
func GetInstanceMetadata() *CloudMetadata {
	return nil
}
