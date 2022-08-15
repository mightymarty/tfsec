package monitor

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	monitor2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/monitor"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) monitor2.Monitor {
	return monitor2.Monitor{
		LogProfiles: adaptLogProfiles(modules),
	}
}

func adaptLogProfiles(modules terraform2.Modules) []monitor2.LogProfile {
	var logProfiles []monitor2.LogProfile

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_monitor_log_profile") {
			logProfiles = append(logProfiles, adaptLogProfile(resource))
		}
	}
	return logProfiles
}

func adaptLogProfile(resource *terraform2.Block) monitor2.LogProfile {

	logProfile := monitor2.LogProfile{
		Metadata: resource.GetMetadata(),
		RetentionPolicy: monitor2.RetentionPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			Days:     types2.IntDefault(0, resource.GetMetadata()),
		},
		Categories: nil,
		Locations:  nil,
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		logProfile.RetentionPolicy.Metadata = retentionPolicyBlock.GetMetadata()
		enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
		logProfile.RetentionPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, resource)
		daysAttr := retentionPolicyBlock.GetAttribute("days")
		logProfile.RetentionPolicy.Days = daysAttr.AsIntValueOrDefault(0, resource)
	}

	if categoriesAttr := resource.GetAttribute("categories"); categoriesAttr.IsNotNil() {
		logProfile.Categories = categoriesAttr.AsStringValues()
	}

	if locationsAttr := resource.GetAttribute("locations"); locationsAttr.IsNotNil() {
		logProfile.Locations = locationsAttr.AsStringValues()
	}

	return logProfile
}
