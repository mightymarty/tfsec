package compute

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptDisks(modules terraform2.Modules) (disks []compute2.Disk) {

	for _, diskBlock := range modules.GetResourcesByType("google_compute_disk") {
		disk := compute2.Disk{
			Metadata: diskBlock.GetMetadata(),
			Name:     diskBlock.GetAttribute("name").AsStringValueOrDefault("", diskBlock),
			Encryption: compute2.DiskEncryption{
				Metadata:   diskBlock.GetMetadata(),
				RawKey:     types2.BytesDefault(nil, diskBlock.GetMetadata()),
				KMSKeyLink: types2.StringDefault("", diskBlock.GetMetadata()),
			},
		}
		if encBlock := diskBlock.GetBlock("disk_encryption_key"); encBlock.IsNotNil() {
			disk.Encryption.Metadata = encBlock.GetMetadata()
			kmsKeyAttr := encBlock.GetAttribute("kms_key_self_link")
			disk.Encryption.KMSKeyLink = kmsKeyAttr.AsStringValueOrDefault("", encBlock)

			if kmsKeyAttr.IsResourceBlockReference("google_kms_crypto_key") {
				if kmsKeyBlock, err := modules.GetReferencedBlock(kmsKeyAttr, encBlock); err == nil {
					disk.Encryption.KMSKeyLink = types2.String(kmsKeyBlock.FullName(), kmsKeyAttr.GetMetadata())
				}
			}

			disk.Encryption.RawKey = encBlock.GetAttribute("raw_key").AsBytesValueOrDefault(nil, encBlock)
		}
		disks = append(disks, disk)
	}

	return disks
}
