package cloudwatch

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	cloudwatch2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudwatch"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) cloudwatch2.CloudWatch {
	return cloudwatch2.CloudWatch{
		LogGroups: adaptLogGroups(modules),
	}
}

func adaptLogGroups(modules terraform2.Modules) []cloudwatch2.LogGroup {
	var logGroups []cloudwatch2.LogGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudwatch_log_group") {
			logGroups = append(logGroups, adaptLogGroup(resource, module))
		}
	}
	return logGroups
}

func adaptLogGroup(resource *terraform2.Block, module *terraform2.Module) cloudwatch2.LogGroup {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	if keyBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource); err == nil {
		KMSKeyIDVal = types.String(keyBlock.FullName(), keyBlock.GetMetadata())
	}

	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return cloudwatch2.LogGroup{
		Metadata:        resource.GetMetadata(),
		Name:            nameVal,
		KMSKeyID:        KMSKeyIDVal,
		RetentionInDays: retentionInDaysVal,
	}
}
