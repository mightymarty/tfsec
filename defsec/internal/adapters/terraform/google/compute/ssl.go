package compute

import (
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptSSLPolicies(modules terraform2.Modules) (policies []compute2.SSLPolicy) {
	for _, policyBlock := range modules.GetResourcesByType("google_compute_ssl_policy") {
		policy := compute2.SSLPolicy{
			Metadata:          policyBlock.GetMetadata(),
			Name:              policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock),
			Profile:           policyBlock.GetAttribute("profile").AsStringValueOrDefault("", policyBlock),
			MinimumTLSVersion: policyBlock.GetAttribute("min_tls_version").AsStringValueOrDefault("TLS_1_0", policyBlock),
		}
		policies = append(policies, policy)
	}
	return policies
}
