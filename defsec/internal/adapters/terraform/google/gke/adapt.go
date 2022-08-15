package gke

import (
	"github.com/google/uuid"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	gke2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/gke"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"github.com/zclconf/go-cty/cty"
)

func Adapt(modules terraform2.Modules) gke2.GKE {
	return gke2.GKE{
		Clusters: (&adapter{
			modules:    modules,
			clusterMap: make(map[string]gke2.Cluster),
		}).adaptClusters(),
	}
}

type adapter struct {
	modules    terraform2.Modules
	clusterMap map[string]gke2.Cluster
}

func (a *adapter) adaptClusters() []gke2.Cluster {
	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("google_container_cluster") {
			a.adaptCluster(resource, module)
		}
	}

	a.adaptNodePools()

	for id, cluster := range a.clusterMap {
		if len(cluster.NodePools) > 0 {
			cluster.NodeConfig = cluster.NodePools[0].NodeConfig
			a.clusterMap[id] = cluster
		}
	}

	var clusters []gke2.Cluster
	for _, cluster := range a.clusterMap {
		clusters = append(clusters, cluster)
	}
	return clusters
}

func (a *adapter) adaptCluster(resource *terraform2.Block, module *terraform2.Module) {

	cluster := gke2.Cluster{
		Metadata:  resource.GetMetadata(),
		NodePools: nil,
		IPAllocationPolicy: gke2.IPAllocationPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuthorizedNetworks: gke2.MasterAuthorizedNetworks{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			CIDRs:    []types2.StringValue{},
		},
		NetworkPolicy: gke2.NetworkPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
		},
		PrivateCluster: gke2.PrivateCluster{
			Metadata:           resource.GetMetadata(),
			EnablePrivateNodes: types2.BoolDefault(false, resource.GetMetadata()),
		},
		LoggingService:    types2.StringDefault("logging.googleapis.com/kubernetes", resource.GetMetadata()),
		MonitoringService: types2.StringDefault("monitoring.googleapis.com/kubernetes", resource.GetMetadata()),
		PodSecurityPolicy: gke2.PodSecurityPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
		},
		MasterAuth: gke2.MasterAuth{
			Metadata: resource.GetMetadata(),
			ClientCertificate: gke2.ClientCertificate{
				Metadata:         resource.GetMetadata(),
				IssueCertificate: types2.BoolDefault(false, resource.GetMetadata()),
			},
			Username: types2.StringDefault("", resource.GetMetadata()),
			Password: types2.StringDefault("", resource.GetMetadata()),
		},
		NodeConfig: gke2.NodeConfig{
			Metadata:  resource.GetMetadata(),
			ImageType: types2.StringDefault("", resource.GetMetadata()),
			WorkloadMetadataConfig: gke2.WorkloadMetadataConfig{
				Metadata:     resource.GetMetadata(),
				NodeMetadata: types2.StringDefault("", resource.GetMetadata()),
			},
			ServiceAccount:        types2.StringDefault("", resource.GetMetadata()),
			EnableLegacyEndpoints: types2.BoolDefault(true, resource.GetMetadata()),
		},
		EnableShieldedNodes:   types2.BoolDefault(true, resource.GetMetadata()),
		EnableLegacyABAC:      types2.BoolDefault(false, resource.GetMetadata()),
		ResourceLabels:        types2.MapDefault(make(map[string]string), resource.GetMetadata()),
		RemoveDefaultNodePool: types2.BoolDefault(false, resource.GetMetadata()),
	}

	if allocBlock := resource.GetBlock("ip_allocation_policy"); allocBlock.IsNotNil() {
		cluster.IPAllocationPolicy.Metadata = allocBlock.GetMetadata()
		cluster.IPAllocationPolicy.Enabled = types2.Bool(true, allocBlock.GetMetadata())
	}

	if blocks := resource.GetBlocks("master_authorized_networks_config"); len(blocks) > 0 {
		cluster.MasterAuthorizedNetworks = adaptMasterAuthNetworksAsBlocks(resource, blocks)
	}

	if policyBlock := resource.GetBlock("network_policy"); policyBlock.IsNotNil() {
		enabledAttr := policyBlock.GetAttribute("enabled")
		cluster.NetworkPolicy.Metadata = policyBlock.GetMetadata()
		cluster.NetworkPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, policyBlock)
	}

	if privBlock := resource.GetBlock("private_cluster_config"); privBlock.IsNotNil() {
		privateNodesEnabledAttr := privBlock.GetAttribute("enable_private_nodes")
		cluster.PrivateCluster.Metadata = privBlock.GetMetadata()
		cluster.PrivateCluster.EnablePrivateNodes = privateNodesEnabledAttr.AsBoolValueOrDefault(false, privBlock)
	}

	loggingAttr := resource.GetAttribute("logging_service")
	cluster.LoggingService = loggingAttr.AsStringValueOrDefault("logging.googleapis.com/kubernetes", resource)
	monitoringServiceAttr := resource.GetAttribute("monitoring_service")
	cluster.MonitoringService = monitoringServiceAttr.AsStringValueOrDefault("monitoring.googleapis.com/kubernetes", resource)

	if policyBlock := resource.GetBlock("pod_security_policy_config"); policyBlock.IsNotNil() {
		enabledAttr := policyBlock.GetAttribute("enabled")
		cluster.PodSecurityPolicy.Metadata = policyBlock.GetMetadata()
		cluster.PodSecurityPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, policyBlock)
	}

	if masterBlock := resource.GetBlock("master_auth"); masterBlock.IsNotNil() {
		cluster.MasterAuth = adaptMasterAuth(masterBlock)
	}

	if configBlock := resource.GetBlock("node_config"); configBlock.IsNotNil() {
		if configBlock.GetBlock("metadata").IsNotNil() {
			cluster.NodeConfig.Metadata = configBlock.GetBlock("metadata").GetMetadata()
		}
		cluster.NodeConfig = adaptNodeConfig(configBlock)
	}

	cluster.EnableShieldedNodes = resource.GetAttribute("enable_shielded_nodes").AsBoolValueOrDefault(true, resource)

	enableLegacyABACAttr := resource.GetAttribute("enable_legacy_abac")
	cluster.EnableLegacyABAC = enableLegacyABACAttr.AsBoolValueOrDefault(false, resource)

	resourceLabelsAttr := resource.GetAttribute("resource_labels")
	if resourceLabelsAttr.IsNotNil() {
		resourceLabels := make(map[string]string)
		_ = resourceLabelsAttr.Each(func(key, val cty.Value) {
			if key.Type() == cty.String && val.Type() == cty.String {
				resourceLabels[key.AsString()] = val.AsString()
			}
		})
		cluster.ResourceLabels = types2.Map(resourceLabels, resourceLabelsAttr.GetMetadata())
	}

	cluster.RemoveDefaultNodePool = resource.GetAttribute("remove_default_node_pool").AsBoolValueOrDefault(false, resource)

	a.clusterMap[resource.ID()] = cluster
}

func (a *adapter) adaptNodePools() {
	for _, nodePoolBlock := range a.modules.GetResourcesByType("google_container_node_pool") {
		a.adaptNodePool(nodePoolBlock)
	}
}

func (a *adapter) adaptNodePool(resource *terraform2.Block) {
	nodeConfig := gke2.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: types2.StringDefault("", resource.GetMetadata()),
		WorkloadMetadataConfig: gke2.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: types2.StringDefault("", resource.GetMetadata()),
		},
		ServiceAccount:        types2.StringDefault("", resource.GetMetadata()),
		EnableLegacyEndpoints: types2.BoolDefault(true, resource.GetMetadata()),
	}

	management := gke2.Management{
		Metadata:          resource.GetMetadata(),
		EnableAutoRepair:  types2.BoolDefault(false, resource.GetMetadata()),
		EnableAutoUpgrade: types2.BoolDefault(false, resource.GetMetadata()),
	}

	if resource.HasChild("management") {
		management.Metadata = resource.GetBlock("management").GetMetadata()

		autoRepairAttr := resource.GetBlock("management").GetAttribute("auto_repair")
		management.EnableAutoRepair = autoRepairAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))

		autoUpgradeAttr := resource.GetBlock("management").GetAttribute("auto_upgrade")
		management.EnableAutoUpgrade = autoUpgradeAttr.AsBoolValueOrDefault(false, resource.GetBlock("management"))
	}

	if resource.HasChild("node_config") {
		nodeConfig = adaptNodeConfig(resource.GetBlock("node_config"))
	}

	nodePool := gke2.NodePool{
		Metadata:   resource.GetMetadata(),
		Management: management,
		NodeConfig: nodeConfig,
	}

	clusterAttr := resource.GetAttribute("cluster")
	if referencedCluster, err := a.modules.GetReferencedBlock(clusterAttr, resource); err == nil {
		if referencedCluster.TypeLabel() == "google_container_cluster" {
			if cluster, ok := a.clusterMap[referencedCluster.ID()]; ok {
				cluster.NodePools = append(cluster.NodePools, nodePool)
				a.clusterMap[referencedCluster.ID()] = cluster
				return
			}
		}
	}

	// we didn't find a cluster to put the nodepool in, so create a placeholder
	a.clusterMap[uuid.NewString()] = gke2.Cluster{
		Metadata:  types2.NewUnmanagedMetadata(),
		NodePools: []gke2.NodePool{nodePool},
	}
}

func adaptNodeConfig(resource *terraform2.Block) gke2.NodeConfig {

	config := gke2.NodeConfig{
		Metadata:  resource.GetMetadata(),
		ImageType: resource.GetAttribute("image_type").AsStringValueOrDefault("", resource),
		WorkloadMetadataConfig: gke2.WorkloadMetadataConfig{
			Metadata:     resource.GetMetadata(),
			NodeMetadata: types2.StringDefault("UNSPECIFIED", resource.GetMetadata()),
		},
		ServiceAccount:        resource.GetAttribute("service_account").AsStringValueOrDefault("", resource),
		EnableLegacyEndpoints: types2.BoolDefault(true, resource.GetMetadata()),
	}

	if metadata := resource.GetAttribute("metadata"); metadata.IsNotNil() {
		legacyMetadata := metadata.MapValue("disable-legacy-endpoints")
		if legacyMetadata.IsWhollyKnown() && legacyMetadata.Type() == cty.Bool {
			config.EnableLegacyEndpoints = types2.Bool(legacyMetadata.False(), metadata.GetMetadata())
		}
	}

	workloadBlock := resource.GetBlock("workload_metadata_config")
	if workloadBlock.IsNotNil() {
		config.WorkloadMetadataConfig.Metadata = workloadBlock.GetMetadata()
		modeAttr := workloadBlock.GetAttribute("node_metadata")
		if modeAttr.IsNil() {
			modeAttr = workloadBlock.GetAttribute("mode") // try newest version
		}
		config.WorkloadMetadataConfig.NodeMetadata = modeAttr.AsStringValueOrDefault("UNSPECIFIED", workloadBlock)
	}

	return config
}

func adaptMasterAuth(resource *terraform2.Block) gke2.MasterAuth {
	clientCert := gke2.ClientCertificate{
		Metadata:         resource.GetMetadata(),
		IssueCertificate: types2.BoolDefault(false, resource.GetMetadata()),
	}

	if resource.HasChild("client_certificate_config") {
		clientCertAttr := resource.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
		clientCert.IssueCertificate = clientCertAttr.AsBoolValueOrDefault(false, resource.GetBlock("client_certificate_config"))
		clientCert.Metadata = resource.GetBlock("client_certificate_config").GetMetadata()
	}

	username := resource.GetAttribute("username").AsStringValueOrDefault("", resource)
	password := resource.GetAttribute("password").AsStringValueOrDefault("", resource)

	return gke2.MasterAuth{
		Metadata:          resource.GetMetadata(),
		ClientCertificate: clientCert,
		Username:          username,
		Password:          password,
	}
}

func adaptMasterAuthNetworksAsBlocks(parent *terraform2.Block, blocks terraform2.Blocks) gke2.MasterAuthorizedNetworks {
	var cidrs []types2.StringValue
	for _, block := range blocks {
		for _, cidrBlock := range block.GetBlocks("cidr_blocks") {
			if cidrAttr := cidrBlock.GetAttribute("cidr_block"); cidrAttr.IsNotNil() {
				cidrs = append(cidrs, cidrAttr.AsStringValues()...)
			}
		}
	}
	enabled := types2.Bool(true, blocks[0].GetMetadata())
	return gke2.MasterAuthorizedNetworks{
		Metadata: blocks[0].GetMetadata(),
		Enabled:  enabled,
		CIDRs:    cidrs,
	}
}
