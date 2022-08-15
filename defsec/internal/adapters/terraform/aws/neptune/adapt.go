package neptune

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	neptune2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/neptune"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) neptune2.Neptune {
	return neptune2.Neptune{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []neptune2.Cluster {
	var clusters []neptune2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_neptune_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform2.Block) neptune2.Cluster {
	cluster := neptune2.Cluster{
		Metadata: resource.GetMetadata(),
		Logging: neptune2.Logging{
			Metadata: resource.GetMetadata(),
			Audit:    types2.BoolDefault(false, resource.GetMetadata()),
		},
		StorageEncrypted: types2.BoolDefault(false, resource.GetMetadata()),
		KMSKeyID:         types2.StringDefault("", resource.GetMetadata()),
	}

	if enableLogExportsAttr := resource.GetAttribute("enable_cloudwatch_logs_exports"); enableLogExportsAttr.IsNotNil() {
		cluster.Logging.Metadata = enableLogExportsAttr.GetMetadata()
		if enableLogExportsAttr.Contains("audit") {
			cluster.Logging.Audit = types2.Bool(true, enableLogExportsAttr.GetMetadata())
		}
	}

	storageEncryptedAttr := resource.GetAttribute("storage_encrypted")
	cluster.StorageEncrypted = storageEncryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyAttr := resource.GetAttribute("kms_key_arn")
	cluster.KMSKeyID = KMSKeyAttr.AsStringValueOrDefault("", resource)

	return cluster
}
