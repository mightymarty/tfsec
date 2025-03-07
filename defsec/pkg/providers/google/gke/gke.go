package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           types.StringValue
	MonitoringService        types.StringValue
	PodSecurityPolicy        PodSecurityPolicy
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      types.BoolValue
	EnableLegacyABAC         types.BoolValue
	ResourceLabels           types.MapValue
	RemoveDefaultNodePool    types.BoolValue
}

type NodeConfig struct {
	types.Metadata
	ImageType              types.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         types.StringValue
	EnableLegacyEndpoints  types.BoolValue
}

type WorkloadMetadataConfig struct {
	types.Metadata
	NodeMetadata types.StringValue
}

type MasterAuth struct {
	types.Metadata
	ClientCertificate ClientCertificate
	Username          types.StringValue
	Password          types.StringValue
}

type ClientCertificate struct {
	types.Metadata
	IssueCertificate types.BoolValue
}

type PodSecurityPolicy struct {
	types.Metadata
	Enabled types.BoolValue
}

type PrivateCluster struct {
	types.Metadata
	EnablePrivateNodes types.BoolValue
}

type NetworkPolicy struct {
	types.Metadata
	Enabled types.BoolValue
}

type MasterAuthorizedNetworks struct {
	types.Metadata
	Enabled types.BoolValue
	CIDRs   []types.StringValue
}

type IPAllocationPolicy struct {
	types.Metadata
	Enabled types.BoolValue
}

type NodePool struct {
	types.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	types.Metadata
	EnableAutoRepair  types.BoolValue
	EnableAutoUpgrade types.BoolValue
}
