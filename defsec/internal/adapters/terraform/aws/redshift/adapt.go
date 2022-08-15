package redshift

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	redshift2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/redshift"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) redshift2.Redshift {
	return redshift2.Redshift{
		Clusters:       adaptClusters(modules),
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []redshift2.Cluster {
	var clusters []redshift2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}
	return clusters
}

func adaptSecurityGroups(modules terraform2.Modules) []redshift2.SecurityGroup {
	var securityGroups []redshift2.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource))
		}
	}
	return securityGroups
}

func adaptCluster(resource *terraform2.Block, module *terraform2.Module) redshift2.Cluster {
	cluster := redshift2.Cluster{
		Metadata: resource.GetMetadata(),
		Encryption: redshift2.Encryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			KMSKeyID: types2.StringDefault("", resource.GetMetadata()),
		},
		SubnetGroupName: types2.StringDefault("", resource.GetMetadata()),
	}

	encryptedAttr := resource.GetAttribute("encrypted")
	cluster.Encryption.Enabled = encryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	cluster.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValueOrDefault("", resource)
	if KMSKeyIDAttr.IsResourceBlockReference("aws_kms_key") {
		if kmsKeyBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource); err == nil {
			cluster.Encryption.KMSKeyID = types2.String(kmsKeyBlock.FullName(), kmsKeyBlock.GetMetadata())
		}
	}

	subnetGroupNameAttr := resource.GetAttribute("cluster_subnet_group_name")
	cluster.SubnetGroupName = subnetGroupNameAttr.AsStringValueOrDefault("", resource)

	return cluster
}

func adaptSecurityGroup(resource *terraform2.Block) redshift2.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	return redshift2.SecurityGroup{
		Metadata:    resource.GetMetadata(),
		Description: descriptionVal,
	}
}
