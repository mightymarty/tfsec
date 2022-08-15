package documentdb

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	documentdb2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/documentdb"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) documentdb2.DocumentDB {
	return documentdb2.DocumentDB{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []documentdb2.Cluster {
	var clusters []documentdb2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_docdb_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform2.Block, module *terraform2.Module) documentdb2.Cluster {
	identifierAttr := resource.GetAttribute("cluster_identifier")
	identifierVal := identifierAttr.AsStringValueOrDefault("", resource)

	var enabledLogExports []types.StringValue
	var instances []documentdb2.Instance

	enabledLogExportsAttr := resource.GetAttribute("enabled_cloudwatch_logs_exports")
	for _, logExport := range enabledLogExportsAttr.AsStringValues() {
		enabledLogExports = append(enabledLogExports, logExport)
	}

	instancesRes := module.GetReferencingResources(resource, "aws_docdb_cluster_instance", "cluster_identifier")
	for _, instanceRes := range instancesRes {
		keyIDAttr := instanceRes.GetAttribute("kms_key_id")
		keyIDVal := keyIDAttr.AsStringValueOrDefault("", instanceRes)

		instances = append(instances, documentdb2.Instance{
			Metadata: instanceRes.GetMetadata(),
			KMSKeyID: keyIDVal,
		})
	}

	storageEncryptedAttr := resource.GetAttribute("storage_encrypted")
	storageEncryptedVal := storageEncryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	return documentdb2.Cluster{
		Metadata:          resource.GetMetadata(),
		Identifier:        identifierVal,
		EnabledLogExports: enabledLogExports,
		Instances:         instances,
		StorageEncrypted:  storageEncryptedVal,
		KMSKeyID:          KMSKeyIDVal,
	}
}
