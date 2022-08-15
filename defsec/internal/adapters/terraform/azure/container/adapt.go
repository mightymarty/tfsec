package container

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	container2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/container"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) container2.Container {
	return container2.Container{
		KubernetesClusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []container2.KubernetesCluster {
	var clusters []container2.KubernetesCluster

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_kubernetes_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform2.Block) container2.KubernetesCluster {

	cluster := container2.KubernetesCluster{
		Metadata: resource.GetMetadata(),
		NetworkProfile: container2.NetworkProfile{
			Metadata:      resource.GetMetadata(),
			NetworkPolicy: types2.StringDefault("", resource.GetMetadata()),
		},
		EnablePrivateCluster:        types2.BoolDefault(false, resource.GetMetadata()),
		APIServerAuthorizedIPRanges: nil,
		RoleBasedAccessControl: container2.RoleBasedAccessControl{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
		},
		AddonProfile: container2.AddonProfile{
			Metadata: resource.GetMetadata(),
			OMSAgent: container2.OMSAgent{
				Metadata: resource.GetMetadata(),
				Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			},
		},
	}

	networkProfileBlock := resource.GetBlock("network_profile")
	if networkProfileBlock.IsNotNil() {
		networkPolicyAttr := networkProfileBlock.GetAttribute("network_policy")
		cluster.NetworkProfile.Metadata = networkProfileBlock.GetMetadata()
		cluster.NetworkProfile.NetworkPolicy = networkPolicyAttr.AsStringValueOrDefault("", networkProfileBlock)
	}

	privateClusterEnabledAttr := resource.GetAttribute("private_cluster_enabled")
	cluster.EnablePrivateCluster = privateClusterEnabledAttr.AsBoolValueOrDefault(false, resource)

	apiServerAuthorizedIPRangesAttr := resource.GetAttribute("api_server_authorized_ip_ranges")
	cluster.APIServerAuthorizedIPRanges = apiServerAuthorizedIPRangesAttr.AsStringValues()

	addonProfileBlock := resource.GetBlock("addon_profile")
	if addonProfileBlock.IsNotNil() {
		cluster.AddonProfile.Metadata = addonProfileBlock.GetMetadata()
		omsAgentBlock := addonProfileBlock.GetBlock("oms_agent")
		if omsAgentBlock.IsNotNil() {
			cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.GetMetadata()
			enabledAttr := omsAgentBlock.GetAttribute("enabled")
			cluster.AddonProfile.OMSAgent.Enabled = enabledAttr.AsBoolValueOrDefault(false, omsAgentBlock)
		}
	}

	// >= azurerm 2.97.0
	if omsAgentBlock := resource.GetBlock("oms_agent"); omsAgentBlock.IsNotNil() {
		cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.GetMetadata()
		cluster.AddonProfile.OMSAgent.Enabled = types2.Bool(true, omsAgentBlock.GetMetadata())
	}

	// azurerm < 2.99.0
	if resource.HasChild("role_based_access_control") {
		roleBasedAccessControlBlock := resource.GetBlock("role_based_access_control")
		rbEnabledAttr := roleBasedAccessControlBlock.GetAttribute("enabled")
		cluster.RoleBasedAccessControl.Metadata = roleBasedAccessControlBlock.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = rbEnabledAttr.AsBoolValueOrDefault(false, roleBasedAccessControlBlock)
	}
	if resource.HasChild("role_based_access_control_enabled") {
		// azurerm >= 2.99.0
		roleBasedAccessControlEnabledAttr := resource.GetAttribute("role_based_access_control_enabled")
		cluster.RoleBasedAccessControl.Metadata = roleBasedAccessControlEnabledAttr.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = roleBasedAccessControlEnabledAttr.AsBoolValueOrDefault(false, resource)
	}

	if resource.HasChild("azure_active_directory_role_based_access_control") {
		azureRoleBasedAccessControl := resource.GetBlock("azure_active_directory_role_based_access_control")
		if azureRoleBasedAccessControl.IsNotNil() {
			enabledAttr := azureRoleBasedAccessControl.GetAttribute("azure_rbac_enabled")
			cluster.RoleBasedAccessControl.Metadata = azureRoleBasedAccessControl.GetMetadata()
			cluster.RoleBasedAccessControl.Enabled = enabledAttr.AsBoolValueOrDefault(false, azureRoleBasedAccessControl)
		}
	}
	return cluster
}
