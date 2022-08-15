package kms

import (
	kms2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/kms"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) kms2.KMS {
	return kms2.KMS{
		Keys: adaptKeys(modules),
	}
}

func adaptKeys(modules terraform2.Modules) []kms2.Key {
	var keys []kms2.Key
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kms_key") {
			keys = append(keys, adaptKey(resource))
		}
	}
	return keys
}

func adaptKey(resource *terraform2.Block) kms2.Key {
	usageAttr := resource.GetAttribute("key_usage")
	usageVal := usageAttr.AsStringValueOrDefault("ENCRYPT_DECRYPT", resource)

	enableKeyRotationAttr := resource.GetAttribute("enable_key_rotation")
	enableKeyRotationVal := enableKeyRotationAttr.AsBoolValueOrDefault(false, resource)

	return kms2.Key{
		Metadata:        resource.GetMetadata(),
		Usage:           usageVal,
		RotationEnabled: enableKeyRotationVal,
	}
}
