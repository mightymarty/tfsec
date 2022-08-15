package container

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckConfiguredNetworkPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0043",
		Provider:    providers2.AzureProvider,
		Service:     "container",
		ShortCode:   "configured-network-policy",
		Summary:     "Ensure AKS cluster has Network Policy configured",
		Impact:      "No network policy is protecting the AKS cluster",
		Resolution:  "Configure a network policy",
		Explanation: `The Kubernetes object type NetworkPolicy should be defined to have opportunity allow or block traffic to pods, as in a Kubernetes cluster configured with default settings, all pods can discover and communicate with each other without any restrictions.`,
		Links: []string{
			"https://kubernetes.io/docs/concepts/services-networking/network-policies",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformConfiguredNetworkPolicyGoodExamples,
			BadExamples:         terraformConfiguredNetworkPolicyBadExamples,
			Links:               terraformConfiguredNetworkPolicyLinks,
			RemediationMarkdown: terraformConfiguredNetworkPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.NetworkProfile.NetworkPolicy.IsEmpty() {
				results.Add(
					"Kubernetes cluster does not have a network policy set.",
					cluster.NetworkProfile.NetworkPolicy,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
