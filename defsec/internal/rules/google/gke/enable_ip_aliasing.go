package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableIpAliasing = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0049",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-ip-aliasing",
		Summary:     "Clusters should have IP aliasing enabled",
		Impact:      "Nodes need a NAT gateway to access local services",
		Resolution:  "Enable IP aliasing",
		Explanation: `IP aliasing allows the reuse of public IPs internally, removing the need for a NAT gateway.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableIpAliasingGoodExamples,
			BadExamples:         terraformEnableIpAliasingBadExamples,
			Links:               terraformEnableIpAliasingLinks,
			RemediationMarkdown: terraformEnableIpAliasingRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.IPAllocationPolicy.Enabled.IsFalse() {
				results.Add(
					"Cluster has IP aliasing disabled.",
					cluster.IPAllocationPolicy.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
