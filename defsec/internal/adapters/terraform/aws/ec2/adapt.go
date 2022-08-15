package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	ec22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ec2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) ec22.EC2 {

	naclAdapter := naclAdapter{naclRuleIDs: modules.GetChildResourceIDMapByType("aws_network_acl_rule")}
	sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("aws_security_group_rule")}

	return ec22.EC2{
		Instances:            getInstances(modules),
		DefaultVPCs:          adaptDefaultVPCs(modules),
		SecurityGroups:       sgAdapter.adaptSecurityGroups(modules),
		NetworkACLs:          naclAdapter.adaptNetworkACLs(modules),
		LaunchConfigurations: adaptLaunchConfigurations(modules),
		LaunchTemplates:      adaptLaunchTemplates(modules),
		Volumes:              adaptVolumes(modules),
	}
}

func getInstances(modules terraform2.Modules) []ec22.Instance {
	var instances []ec22.Instance

	blocks := modules.GetResourcesByType("aws_instance")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		instance := ec22.Instance{
			Metadata:        b.GetMetadata(),
			MetadataOptions: metadataOptions,
			UserData:        userData,
			SecurityGroups:  nil,
			RootBlockDevice: &ec22.BlockDevice{
				Metadata:  b.GetMetadata(),
				Encrypted: types.BoolDefault(false, b.GetMetadata()),
			},
			EBSBlockDevices: nil,
		}

		if rootBlockDevice := b.GetBlock("root_block_device"); rootBlockDevice.IsNotNil() {
			instance.RootBlockDevice.Metadata = rootBlockDevice.GetMetadata()
			instance.RootBlockDevice.Encrypted = rootBlockDevice.GetAttribute("encrypted").AsBoolValueOrDefault(false, b)
		}

		for _, ebsBlock := range b.GetBlocks("ebs_block_device") {
			instance.EBSBlockDevices = append(instance.EBSBlockDevices, &ec22.BlockDevice{
				Metadata:  ebsBlock.GetMetadata(),
				Encrypted: ebsBlock.GetAttribute("encrypted").AsBoolValueOrDefault(false, b),
			})
		}

		for _, resource := range modules.GetResourcesByType("aws_ebs_encryption_by_default") {
			if resource.GetAttribute("enabled").NotEqual(false) {
				instance.RootBlockDevice.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				for i := 0; i < len(instance.EBSBlockDevices); i++ {
					ebs := instance.EBSBlockDevices[i]
					ebs.Encrypted = types.BoolDefault(true, resource.GetMetadata())
				}
			}
		}

		instances = append(instances, instance)
	}

	return instances
}
