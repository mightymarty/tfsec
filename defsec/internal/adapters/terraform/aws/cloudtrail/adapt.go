package cloudtrail

import (
	cloudtrail2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudtrail"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) cloudtrail2.CloudTrail {
	return cloudtrail2.CloudTrail{
		Trails: adaptTrails(modules),
	}
}

func adaptTrails(modules terraform2.Modules) []cloudtrail2.Trail {
	var trails []cloudtrail2.Trail

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudtrail") {
			trails = append(trails, adaptTrail(resource))
		}
	}
	return trails
}

func adaptTrail(resource *terraform2.Block) cloudtrail2.Trail {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	enableLogFileValidationAttr := resource.GetAttribute("enable_log_file_validation")
	enableLogFileValidationVal := enableLogFileValidationAttr.AsBoolValueOrDefault(false, resource)

	isMultiRegionAttr := resource.GetAttribute("is_multi_region_trail")
	isMultiRegionVal := isMultiRegionAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	return cloudtrail2.Trail{
		Metadata:                resource.GetMetadata(),
		Name:                    nameVal,
		EnableLogFileValidation: enableLogFileValidationVal,
		IsMultiRegion:           isMultiRegionVal,
		KMSKeyID:                KMSKeyIDVal,
		BucketName:              resource.GetAttribute("s3_bucket_name").AsStringValueOrDefault("", resource),
	}
}
