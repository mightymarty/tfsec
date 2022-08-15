package synapse

import (
	synapse2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/synapse"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) synapse2.Synapse {
	return synapse2.Synapse{
		Workspaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules terraform2.Modules) []synapse2.Workspace {
	var workspaces []synapse2.Workspace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_synapse_workspace") {
			workspaces = append(workspaces, adaptWorkspace(resource))
		}
	}
	return workspaces
}

func adaptWorkspace(resource *terraform2.Block) synapse2.Workspace {
	enableManagedVNAttr := resource.GetAttribute("managed_virtual_network_enabled")
	enableManagedVNVal := enableManagedVNAttr.AsBoolValueOrDefault(false, resource)

	return synapse2.Workspace{
		Metadata:                    resource.GetMetadata(),
		EnableManagedVirtualNetwork: enableManagedVNVal,
	}
}
