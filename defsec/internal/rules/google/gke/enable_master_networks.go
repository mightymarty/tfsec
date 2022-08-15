package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableMasterNetworks = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0061",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-master-networks",
		Summary:     "Master authorized networks should be configured on GKE clusters",
		Impact:      "Unrestricted network access to the master",
		Resolution:  "Enable master authorized networks",
		Explanation: `Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableMasterNetworksGoodExamples,
			BadExamples:         terraformEnableMasterNetworksBadExamples,
			Links:               terraformEnableMasterNetworksLinks,
			RemediationMarkdown: terraformEnableMasterNetworksRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.MasterAuthorizedNetworks.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have master authorized networks enabled.",
					cluster.MasterAuthorizedNetworks.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
