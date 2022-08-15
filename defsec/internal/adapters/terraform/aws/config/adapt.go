package config

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	config2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/config"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) config2.Config {
	return config2.Config{
		ConfigurationAggregrator: adaptConfigurationAggregrator(modules),
	}
}

func adaptConfigurationAggregrator(modules terraform2.Modules) config2.ConfigurationAggregrator {
	configurationAggregrator := config2.ConfigurationAggregrator{
		Metadata:         types2.NewUnmanagedMetadata(),
		SourceAllRegions: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
		IsDefined:        false,
	}

	for _, resource := range modules.GetResourcesByType("aws_config_configuration_aggregator") {
		configurationAggregrator.Metadata = resource.GetMetadata()
		configurationAggregrator.IsDefined = true

		aggregationBlock := resource.GetFirstMatchingBlock("account_aggregation_source", "organization_aggregation_source")
		if aggregationBlock.IsNil() {
			configurationAggregrator.SourceAllRegions = types2.Bool(false, resource.GetMetadata())
		} else {
			allRegionsAttr := aggregationBlock.GetAttribute("all_regions")
			allRegionsVal := allRegionsAttr.AsBoolValueOrDefault(false, aggregationBlock)
			configurationAggregrator.SourceAllRegions = allRegionsVal
		}
	}
	return configurationAggregrator
}
