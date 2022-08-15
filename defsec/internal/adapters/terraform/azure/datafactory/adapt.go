package datafactory

import (
	datafactory2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/datafactory"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) datafactory2.DataFactory {
	return datafactory2.DataFactory{
		DataFactories: adaptFactories(modules),
	}
}

func adaptFactories(modules terraform2.Modules) []datafactory2.Factory {
	var factories []datafactory2.Factory

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_data_factory") {
			factories = append(factories, adaptFactory(resource))
		}
	}
	return factories
}

func adaptFactory(resource *terraform2.Block) datafactory2.Factory {
	enablePublicNetworkAttr := resource.GetAttribute("public_network_enabled")
	enablePublicNetworkVal := enablePublicNetworkAttr.AsBoolValueOrDefault(true, resource)

	return datafactory2.Factory{
		Metadata:            resource.GetMetadata(),
		EnablePublicNetwork: enablePublicNetworkVal,
	}
}
