package compute

import (
	"encoding/base64"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) compute2.Compute {
	return adaptCompute(modules)
}

func adaptCompute(modules terraform2.Modules) compute2.Compute {

	var managedDisks []compute2.ManagedDisk
	var linuxVirtualMachines []compute2.LinuxVirtualMachine
	var windowsVirtualMachines []compute2.WindowsVirtualMachine

	for _, module := range modules {

		for _, resource := range module.GetResourcesByType("azurerm_linux_virtual_machine") {
			linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_windows_virtual_machine") {
			windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_virtual_machine") {
			if resource.HasChild("os_profile_linux_config") {
				linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
			} else if resource.HasChild("os_profile_windows_config") {
				windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
			}
		}
		for _, resource := range module.GetResourcesByType("azurerm_managed_disk") {
			managedDisks = append(managedDisks, adaptManagedDisk(resource))
		}
	}

	return compute2.Compute{
		LinuxVirtualMachines:   linuxVirtualMachines,
		WindowsVirtualMachines: windowsVirtualMachines,
		ManagedDisks:           managedDisks,
	}
}

func adaptManagedDisk(resource *terraform2.Block) compute2.ManagedDisk {

	disk := compute2.ManagedDisk{
		Metadata: resource.GetMetadata(),
		Encryption: compute2.Encryption{
			Metadata: resource.GetMetadata(),
			// encryption is enabled by default - https://github.com/hashicorp/terraform-provider-azurerm/blob/baf55926fe813011003ee4fb0e8e6134fcfcca87/internal/services/compute/managed_disk_resource.go#L288
			Enabled: types2.BoolDefault(true, resource.GetMetadata()),
		},
	}

	encryptionBlock := resource.GetBlock("encryption_settings")
	if encryptionBlock.IsNotNil() {
		disk.Encryption.Metadata = encryptionBlock.GetMetadata()
		enabledAttr := encryptionBlock.GetAttribute("enabled")
		disk.Encryption.Enabled = enabledAttr.AsBoolValueOrDefault(true, encryptionBlock)
	}

	return disk
}

func adaptLinuxVM(resource *terraform2.Block) compute2.LinuxVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}
	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := types2.StringDefault("", workingBlock.GetMetadata())
	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = types2.String(string(encoded), customDataAttr.GetMetadata())
	}

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		workingBlock = resource.GetBlock("os_profile_linux_config")
	}
	disablePasswordAuthAttr := workingBlock.GetAttribute("disable_password_authentication")
	disablePasswordAuthVal := disablePasswordAuthAttr.AsBoolValueOrDefault(true, workingBlock)

	return compute2.LinuxVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute2.VirtualMachine{
			Metadata:   resource.GetMetadata(),
			CustomData: customDataVal,
		},
		OSProfileLinuxConfig: compute2.OSProfileLinuxConfig{
			Metadata:                      resource.GetMetadata(),
			DisablePasswordAuthentication: disablePasswordAuthVal,
		},
	}
}

func adaptWindowsVM(resource *terraform2.Block) compute2.WindowsVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}

	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := types2.StringDefault("", workingBlock.GetMetadata())

	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = types2.String(string(encoded), customDataAttr.GetMetadata())
	}

	return compute2.WindowsVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute2.VirtualMachine{
			Metadata:   resource.GetMetadata(),
			CustomData: customDataVal,
		},
	}
}
