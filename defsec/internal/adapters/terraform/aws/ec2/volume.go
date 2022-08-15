package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	ec22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ec2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptVolumes(modules terraform2.Modules) []ec22.Volume {
	var volumes []ec22.Volume
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ebs_volume") {
			volumes = append(volumes, adaptVolume(resource, module))
		}
	}
	return volumes
}

func adaptVolume(resource *terraform2.Block, module *terraform2.Module) ec22.Volume {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	kmsKeyAttr := resource.GetAttribute("kms_key_id")
	kmsKeyVal := kmsKeyAttr.AsStringValueOrDefault("", resource)

	if kmsKeyAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(kmsKeyAttr, resource); err == nil {
			kmsKeyVal = types.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}

	return ec22.Volume{
		Metadata: resource.GetMetadata(),
		Encryption: ec22.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  encryptedVal,
			KMSKeyID: kmsKeyVal,
		},
	}
}
