package ec2

import (
	"encoding/base64"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	ec22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ec2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptLaunchTemplates(modules terraform2.Modules) (templates []ec22.LaunchTemplate) {

	blocks := modules.GetResourcesByType("aws_launch_template")

	for _, b := range blocks {

		metadataOptions := getMetadataOptions(b)
		userData := b.GetAttribute("user_data").AsStringValueOrDefault("", b)

		templates = append(templates, ec22.LaunchTemplate{
			Metadata: b.GetMetadata(),
			Instance: ec22.Instance{
				Metadata:        b.GetMetadata(),
				MetadataOptions: metadataOptions,
				UserData:        userData,
				SecurityGroups:  nil,
				RootBlockDevice: nil,
				EBSBlockDevices: nil,
			},
		})
	}

	return templates
}

func adaptLaunchConfigurations(modules terraform2.Modules) []ec22.LaunchConfiguration {
	var launchConfigurations []ec22.LaunchConfiguration

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_launch_configuration") {
			launchConfig := adaptLaunchConfiguration(resource)
			for _, resource := range module.GetResourcesByType("aws_ebs_encryption_by_default") {
				if resource.GetAttribute("enabled").NotEqual(false) {
					launchConfig.RootBlockDevice.Encrypted = types2.BoolDefault(true, resource.GetMetadata())
					for i := 0; i < len(launchConfig.EBSBlockDevices); i++ {
						ebs := launchConfig.EBSBlockDevices[i]
						ebs.Encrypted = types2.BoolDefault(true, resource.GetMetadata())
					}
				}
			}
			launchConfigurations = append(launchConfigurations, launchConfig)
		}
	}
	return launchConfigurations
}

func adaptLaunchConfiguration(resource *terraform2.Block) ec22.LaunchConfiguration {
	launchConfig := ec22.LaunchConfiguration{
		Metadata:          resource.GetMetadata(),
		Name:              types2.StringDefault("", resource.GetMetadata()),
		AssociatePublicIP: resource.GetAttribute("associate_public_ip_address").AsBoolValueOrDefault(false, resource),
		RootBlockDevice: &ec22.BlockDevice{
			Metadata:  resource.GetMetadata(),
			Encrypted: types2.BoolDefault(false, resource.GetMetadata()),
		},
		EBSBlockDevices: nil,
		MetadataOptions: getMetadataOptions(resource),
		UserData:        types2.StringDefault("", resource.GetMetadata()),
	}

	if resource.TypeLabel() == "aws_launch_configuration" {
		nameAttr := resource.GetAttribute("name")
		launchConfig.Name = nameAttr.AsStringValueOrDefault("", resource)
	}

	if rootBlockDeviceBlock := resource.GetBlock("root_block_device"); rootBlockDeviceBlock.IsNotNil() {
		encryptedAttr := rootBlockDeviceBlock.GetAttribute("encrypted")
		launchConfig.RootBlockDevice.Encrypted = encryptedAttr.AsBoolValueOrDefault(false, rootBlockDeviceBlock)
		launchConfig.RootBlockDevice.Metadata = rootBlockDeviceBlock.GetMetadata()
	}

	EBSBlockDevicesBlocks := resource.GetBlocks("ebs_block_device")
	for _, EBSBlockDevicesBlock := range EBSBlockDevicesBlocks {
		encryptedAttr := EBSBlockDevicesBlock.GetAttribute("encrypted")
		encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, EBSBlockDevicesBlock)
		launchConfig.EBSBlockDevices = append(launchConfig.EBSBlockDevices, &ec22.BlockDevice{
			Metadata:  EBSBlockDevicesBlock.GetMetadata(),
			Encrypted: encryptedVal,
		})
	}

	if userDataAttr := resource.GetAttribute("user_data"); userDataAttr.IsNotNil() {
		launchConfig.UserData = userDataAttr.AsStringValueOrDefault("", resource)
	} else if userDataBase64Attr := resource.GetAttribute("user_data_base64"); userDataBase64Attr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(userDataBase64Attr.Value().AsString())
		if err == nil {
			launchConfig.UserData = types2.String(string(encoded), userDataBase64Attr.GetMetadata())
		}
	}

	return launchConfig
}

func getMetadataOptions(b *terraform2.Block) ec22.MetadataOptions {
	options := ec22.MetadataOptions{
		Metadata:     b.GetMetadata(),
		HttpTokens:   types2.StringDefault("", b.GetMetadata()),
		HttpEndpoint: types2.StringDefault("", b.GetMetadata()),
	}

	if metadataOptions := b.GetBlock("metadata_options"); metadataOptions.IsNotNil() {
		options.Metadata = metadataOptions.GetMetadata()
		options.HttpTokens = metadataOptions.GetAttribute("http_tokens").AsStringValueOrDefault("", metadataOptions)
		options.HttpEndpoint = metadataOptions.GetAttribute("http_endpoint").AsStringValueOrDefault("", metadataOptions)
	}

	return options
}
