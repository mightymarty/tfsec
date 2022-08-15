package elasticache

import (
	elasticache2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elasticache"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) elasticache2.ElastiCache {
	return elasticache2.ElastiCache{
		Clusters:          adaptClusters(modules),
		ReplicationGroups: adaptReplicationGroups(modules),
		SecurityGroups:    adaptSecurityGroups(modules),
	}
}
func adaptClusters(modules terraform2.Modules) []elasticache2.Cluster {
	var clusters []elasticache2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptReplicationGroups(modules terraform2.Modules) []elasticache2.ReplicationGroup {
	var replicationGroups []elasticache2.ReplicationGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_replication_group") {
			replicationGroups = append(replicationGroups, adaptReplicationGroup(resource))
		}
	}
	return replicationGroups
}

func adaptSecurityGroups(modules terraform2.Modules) []elasticache2.SecurityGroup {
	var securityGroups []elasticache2.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticache_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource))
		}
	}
	return securityGroups
}

func adaptCluster(resource *terraform2.Block) elasticache2.Cluster {
	engineAttr := resource.GetAttribute("engine")
	engineVal := engineAttr.AsStringValueOrDefault("", resource)

	nodeTypeAttr := resource.GetAttribute("node_type")
	nodeTypeVal := nodeTypeAttr.AsStringValueOrDefault("", resource)

	snapshotRetentionAttr := resource.GetAttribute("snapshot_retention_limit")
	snapshotRetentionVal := snapshotRetentionAttr.AsIntValueOrDefault(0, resource)

	return elasticache2.Cluster{
		Metadata:               resource.GetMetadata(),
		Engine:                 engineVal,
		NodeType:               nodeTypeVal,
		SnapshotRetentionLimit: snapshotRetentionVal,
	}
}

func adaptReplicationGroup(resource *terraform2.Block) elasticache2.ReplicationGroup {
	transitEncryptionAttr := resource.GetAttribute("transit_encryption_enabled")
	transitEncryptionVal := transitEncryptionAttr.AsBoolValueOrDefault(false, resource)

	atRestEncryptionAttr := resource.GetAttribute("at_rest_encryption_enabled")
	atRestEncryptionVal := atRestEncryptionAttr.AsBoolValueOrDefault(false, resource)

	return elasticache2.ReplicationGroup{
		Metadata:                 resource.GetMetadata(),
		TransitEncryptionEnabled: transitEncryptionVal,
		AtRestEncryptionEnabled:  atRestEncryptionVal,
	}
}

func adaptSecurityGroup(resource *terraform2.Block) elasticache2.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	return elasticache2.SecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: descriptionVal,
	}
}
