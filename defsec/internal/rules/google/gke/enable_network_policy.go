package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableNetworkPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0056",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-network-policy",
		Summary:     "Network Policy should be enabled on GKE clusters",
		Impact:      "Unrestricted inter-cluster communication",
		Resolution:  "Enable network policy",
		Explanation: `Enabling a network policy allows the segregation of network traffic by namespace`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableNetworkPolicyGoodExamples,
			BadExamples:         terraformEnableNetworkPolicyBadExamples,
			Links:               terraformEnableNetworkPolicyLinks,
			RemediationMarkdown: terraformEnableNetworkPolicyRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.NetworkPolicy.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have a network policy enabled.",
					cluster.NetworkPolicy.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
