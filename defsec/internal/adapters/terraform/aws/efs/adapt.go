package efs

import (
	efs2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/efs"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) efs2.EFS {
	return efs2.EFS{
		FileSystems: adaptFileSystems(modules),
	}
}

func adaptFileSystems(modules terraform2.Modules) []efs2.FileSystem {
	var filesystems []efs2.FileSystem
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_efs_file_system") {
			filesystems = append(filesystems, adaptFileSystem(resource))
		}
	}
	return filesystems
}

func adaptFileSystem(resource *terraform2.Block) efs2.FileSystem {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	return efs2.FileSystem{
		Metadata:  resource.GetMetadata(),
		Encrypted: encryptedVal,
	}
}
