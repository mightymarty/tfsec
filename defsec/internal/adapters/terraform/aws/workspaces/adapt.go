package workspaces

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	workspaces2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/workspaces"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) workspaces2.WorkSpaces {
	return workspaces2.WorkSpaces{
		WorkSpaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules terraform2.Modules) []workspaces2.WorkSpace {
	var workspaces []workspaces2.WorkSpace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_workspaces_workspace") {
			workspaces = append(workspaces, adaptWorkspace(resource))
		}
	}
	return workspaces
}

func adaptWorkspace(resource *terraform2.Block) workspaces2.WorkSpace {

	workspace := workspaces2.WorkSpace{
		Metadata: resource.GetMetadata(),
		RootVolume: workspaces2.Volume{
			Metadata: resource.GetMetadata(),
			Encryption: workspaces2.Encryption{
				Metadata: resource.GetMetadata(),
				Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			},
		},
		UserVolume: workspaces2.Volume{
			Metadata: resource.GetMetadata(),
			Encryption: workspaces2.Encryption{
				Metadata: resource.GetMetadata(),
				Enabled:  types.BoolDefault(false, resource.GetMetadata()),
			},
		},
	}
	if rootVolumeEncryptAttr := resource.GetAttribute("root_volume_encryption_enabled"); rootVolumeEncryptAttr.IsNotNil() {
		workspace.RootVolume.Metadata = rootVolumeEncryptAttr.GetMetadata()
		workspace.RootVolume.Encryption.Metadata = rootVolumeEncryptAttr.GetMetadata()
		workspace.RootVolume.Encryption.Enabled = rootVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)
	}

	if userVolumeEncryptAttr := resource.GetAttribute("user_volume_encryption_enabled"); userVolumeEncryptAttr.IsNotNil() {
		workspace.UserVolume.Metadata = userVolumeEncryptAttr.GetMetadata()
		workspace.UserVolume.Encryption.Metadata = userVolumeEncryptAttr.GetMetadata()
		workspace.UserVolume.Encryption.Enabled = userVolumeEncryptAttr.AsBoolValueOrDefault(false, resource)
	}

	return workspace
}
