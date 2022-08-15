package athena

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	athena2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/athena"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) athena2.Athena {
	return athena2.Athena{
		Databases:  adaptDatabases(modules),
		Workgroups: adaptWorkgroups(modules),
	}
}

func adaptDatabases(modules terraform2.Modules) []athena2.Database {
	var databases []athena2.Database
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_athena_database") {
			databases = append(databases, adaptDatabase(resource))
		}
	}
	return databases
}

func adaptWorkgroups(modules terraform2.Modules) []athena2.Workgroup {
	var workgroups []athena2.Workgroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_athena_workgroup") {
			workgroups = append(workgroups, adaptWorkgroup(resource))
		}
	}
	return workgroups
}

func adaptDatabase(resource *terraform2.Block) athena2.Database {
	database := athena2.Database{
		Metadata: resource.GetMetadata(),
		Name:     resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Encryption: athena2.EncryptionConfiguration{
			Metadata: resource.GetMetadata(),
			Type:     types2.StringDefault("", resource.GetMetadata()),
		},
	}
	if encryptionConfigBlock := resource.GetBlock("encryption_configuration"); encryptionConfigBlock.IsNotNil() {
		database.Encryption.Metadata = encryptionConfigBlock.GetMetadata()
		encryptionOptionAttr := encryptionConfigBlock.GetAttribute("encryption_option")
		database.Encryption.Type = encryptionOptionAttr.AsStringValueOrDefault("", encryptionConfigBlock)
	}

	return database
}

func adaptWorkgroup(resource *terraform2.Block) athena2.Workgroup {
	workgroup := athena2.Workgroup{
		Metadata: resource.GetMetadata(),
		Name:     resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Encryption: athena2.EncryptionConfiguration{
			Metadata: resource.GetMetadata(),
			Type:     types2.StringDefault("", resource.GetMetadata()),
		},
		EnforceConfiguration: types2.BoolDefault(false, resource.GetMetadata()),
	}

	if configBlock := resource.GetBlock("configuration"); configBlock.IsNotNil() {

		enforceWGConfigAttr := configBlock.GetAttribute("enforce_workgroup_configuration")
		workgroup.EnforceConfiguration = enforceWGConfigAttr.AsBoolValueOrDefault(true, configBlock)

		if resultConfigBlock := configBlock.GetBlock("result_configuration"); configBlock.IsNotNil() {
			if encryptionConfigBlock := resultConfigBlock.GetBlock("encryption_configuration"); encryptionConfigBlock.IsNotNil() {
				encryptionOptionAttr := encryptionConfigBlock.GetAttribute("encryption_option")
				workgroup.Encryption.Metadata = encryptionConfigBlock.GetMetadata()
				workgroup.Encryption.Type = encryptionOptionAttr.AsStringValueOrDefault("", encryptionConfigBlock)
			}
		}
	}

	return workgroup
}
