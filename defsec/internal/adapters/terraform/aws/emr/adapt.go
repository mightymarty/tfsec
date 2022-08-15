package emr

import (
	emr2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/emr"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) emr2.EMR {
	return emr2.EMR{
		Clusters:              adaptClusters(modules),
		SecurityConfiguration: adaptSecurityConfigurations(modules),
	}
}
func adaptClusters(modules terraform2.Modules) []emr2.Cluster {
	var clusters []emr2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_emr_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform2.Block) emr2.Cluster {

	return emr2.Cluster{
		Metadata: resource.GetMetadata(),
	}
}

func adaptSecurityConfigurations(modules terraform2.Modules) []emr2.SecurityConfiguration {
	var securityConfiguration []emr2.SecurityConfiguration
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_emr_security_configuration") {
			securityConfiguration = append(securityConfiguration, adaptSecurityConfiguration(resource))
		}
	}
	return securityConfiguration
}

func adaptSecurityConfiguration(resource *terraform2.Block) emr2.SecurityConfiguration {

	return emr2.SecurityConfiguration{
		Metadata:      resource.GetMetadata(),
		Name:          resource.GetAttribute("name").AsStringValueOrDefault("", resource),
		Configuration: resource.GetAttribute("configuration").AsStringValueOrDefault("", resource),
	}

}
