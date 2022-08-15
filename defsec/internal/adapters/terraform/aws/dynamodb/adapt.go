package dynamodb

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	dynamodb2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/dynamodb"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) dynamodb2.DynamoDB {
	return dynamodb2.DynamoDB{
		DAXClusters: adaptClusters(modules),
		Tables:      adaptTables(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []dynamodb2.DAXCluster {
	var clusters []dynamodb2.DAXCluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dax_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptTables(modules terraform2.Modules) []dynamodb2.Table {
	var tables []dynamodb2.Table
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_dynamodb_table") {
			tables = append(tables, adaptTable(resource, module))
		}
	}
	return tables
}

func adaptCluster(resource *terraform2.Block, module *terraform2.Module) dynamodb2.DAXCluster {

	cluster := dynamodb2.DAXCluster{
		Metadata: resource.GetMetadata(),
		ServerSideEncryption: dynamodb2.ServerSideEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: types2.StringDefault("", resource.GetMetadata()),
		},
		PointInTimeRecovery: types2.BoolDefault(false, resource.GetMetadata()),
	}

	if ssEncryptionBlock := resource.GetBlock("server_side_encryption"); ssEncryptionBlock.IsNotNil() {
		cluster.ServerSideEncryption.Metadata = ssEncryptionBlock.GetMetadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		cluster.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		cluster.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return cluster
}

func adaptTable(resource *terraform2.Block, module *terraform2.Module) dynamodb2.Table {

	table := dynamodb2.Table{
		Metadata: resource.GetMetadata(),
		ServerSideEncryption: dynamodb2.ServerSideEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: types2.StringDefault("", resource.GetMetadata()),
		},
		PointInTimeRecovery: types2.BoolDefault(false, resource.GetMetadata()),
	}

	if ssEncryptionBlock := resource.GetBlock("server_side_encryption"); ssEncryptionBlock.IsNotNil() {
		table.ServerSideEncryption.Metadata = ssEncryptionBlock.GetMetadata()
		enabledAttr := ssEncryptionBlock.GetAttribute("enabled")
		table.ServerSideEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, ssEncryptionBlock)

		kmsKeyIdAttr := ssEncryptionBlock.GetAttribute("kms_key_arn")
		table.ServerSideEncryption.KMSKeyID = kmsKeyIdAttr.AsStringValueOrDefault("alias/aws/dynamodb", ssEncryptionBlock)

		kmsBlock, err := module.GetReferencedBlock(kmsKeyIdAttr, resource)
		if err == nil && kmsBlock.IsNotNil() {
			table.ServerSideEncryption.KMSKeyID = types2.String(kmsBlock.FullName(), kmsBlock.GetMetadata())
		}
	}

	if recoveryBlock := resource.GetBlock("point_in_time_recovery"); recoveryBlock.IsNotNil() {
		recoveryEnabledAttr := recoveryBlock.GetAttribute("enabled")
		table.PointInTimeRecovery = recoveryEnabledAttr.AsBoolValueOrDefault(false, recoveryBlock)
	}

	return table
}
