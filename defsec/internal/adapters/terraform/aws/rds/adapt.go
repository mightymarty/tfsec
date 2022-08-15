package rds

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	rds2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/rds"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) rds2.RDS {
	return rds2.RDS{
		Instances: getInstances(modules),
		Clusters:  getClusters(modules),
		Classic:   getClassic(modules),
	}
}

func getInstances(modules terraform2.Modules) (instances []rds2.Instance) {
	for _, resource := range modules.GetResourcesByType("aws_db_instance") {
		instances = append(instances, adaptInstance(resource, modules))
	}

	return instances
}

func getClusters(modules terraform2.Modules) (clusters []rds2.Cluster) {

	rdsInstanceMaps := modules.GetChildResourceIDMapByType("aws_rds_cluster_instance")
	for _, resource := range modules.GetResourcesByType("aws_rds_cluster") {
		cluster, instanceIDs := adaptCluster(resource, modules)
		for _, id := range instanceIDs {
			rdsInstanceMaps.Resolve(id)
		}
		clusters = append(clusters, cluster)
	}

	orphanResources := modules.GetResourceByIDs(rdsInstanceMaps.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := rds2.Cluster{
			Metadata:                  types2.NewUnmanagedMetadata(),
			BackupRetentionPeriodDays: types2.IntDefault(1, types2.NewUnmanagedMetadata()),
			ReplicationSourceARN:      types2.StringDefault("", types2.NewUnmanagedMetadata()),
			PerformanceInsights: rds2.PerformanceInsights{
				Metadata: types2.NewUnmanagedMetadata(),
				Enabled:  types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				KMSKeyID: types2.StringDefault("", types2.NewUnmanagedMetadata()),
			},
			Instances: nil,
			Encryption: rds2.Encryption{
				Metadata:       types2.NewUnmanagedMetadata(),
				EncryptStorage: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				KMSKeyID:       types2.StringDefault("", types2.NewUnmanagedMetadata()),
			},
		}
		for _, orphan := range orphanResources {
			orphanage.Instances = append(orphanage.Instances, adaptClusterInstance(orphan, modules))
		}
		clusters = append(clusters, orphanage)
	}

	return clusters
}

func getClassic(modules terraform2.Modules) (classic rds2.Classic) {

	var classicSecurityGroups []rds2.DBSecurityGroup

	for _, resource := range modules.GetResourcesByType("aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group") {
		classicSecurityGroups = append(classicSecurityGroups, adaptClassicDBSecurityGroup(resource))
	}

	classic.DBSecurityGroups = classicSecurityGroups
	return classic
}

func adaptClusterInstance(resource *terraform2.Block, modules terraform2.Modules) rds2.ClusterInstance {
	clusterIdAttr := resource.GetAttribute("cluster_identifier")
	clusterId := clusterIdAttr.AsStringValueOrDefault("", resource)

	if clusterIdAttr.IsResourceBlockReference("aws_rds_cluster") {
		if referenced, err := modules.GetReferencedBlock(clusterIdAttr, resource); err == nil {
			clusterId = types2.String(referenced.FullName(), referenced.GetMetadata())
		}
	}

	return rds2.ClusterInstance{
		Metadata:          resource.GetMetadata(),
		ClusterIdentifier: clusterId,
		Instance:          adaptInstance(resource, modules),
	}
}

func adaptClassicDBSecurityGroup(resource *terraform2.Block) rds2.DBSecurityGroup {
	return rds2.DBSecurityGroup{
		Metadata: resource.GetMetadata(),
	}
}

func adaptInstance(resource *terraform2.Block, modules terraform2.Modules) rds2.Instance {
	replicaSource := resource.GetAttribute("replicate_source_db")
	replicaSourceValue := ""
	if replicaSource.IsNotNil() {
		if referenced, err := modules.GetReferencedBlock(replicaSource, resource); err == nil {
			replicaSourceValue = referenced.ID()
		}
	}
	return rds2.Instance{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:      types2.StringExplicit(replicaSourceValue, resource.GetMetadata()),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Encryption:                adaptEncryption(resource),
		PublicAccess:              resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(false, resource),
	}
}

func adaptCluster(resource *terraform2.Block, modules terraform2.Modules) (rds2.Cluster, []string) {

	clusterInstances, ids := getClusterInstances(resource, modules)

	return rds2.Cluster{
		Metadata:                  resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(1, resource),
		ReplicationSourceARN:      resource.GetAttribute("replication_source_identifier").AsStringValueOrDefault("", resource),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Instances:                 clusterInstances,
		Encryption:                adaptEncryption(resource),
	}, ids
}

func getClusterInstances(resource *terraform2.Block, modules terraform2.Modules) (clusterInstances []rds2.ClusterInstance, instanceIDs []string) {
	clusterInstanceResources := modules.GetReferencingResources(resource, "aws_rds_cluster_instance", "cluster_identifier")

	for _, ciResource := range clusterInstanceResources {
		instanceIDs = append(instanceIDs, ciResource.ID())
		clusterInstances = append(clusterInstances, adaptClusterInstance(ciResource, modules))
	}
	return clusterInstances, instanceIDs
}

func adaptPerformanceInsights(resource *terraform2.Block) rds2.PerformanceInsights {
	return rds2.PerformanceInsights{
		Metadata: resource.GetMetadata(),
		Enabled:  resource.GetAttribute("performance_insights_enabled").AsBoolValueOrDefault(false, resource),
		KMSKeyID: resource.GetAttribute("performance_insights_kms_key_id").AsStringValueOrDefault("", resource),
	}
}

func adaptEncryption(resource *terraform2.Block) rds2.Encryption {
	return rds2.Encryption{
		Metadata:       resource.GetMetadata(),
		EncryptStorage: resource.GetAttribute("storage_encrypted").AsBoolValueOrDefault(false, resource),
		KMSKeyID:       resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
	}
}
