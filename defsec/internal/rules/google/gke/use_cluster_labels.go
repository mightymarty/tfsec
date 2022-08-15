package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseClusterLabels = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0051",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-cluster-labels",
		Summary:     "Clusters should be configured with Labels",
		Impact:      "Asset management can be limited/more difficult",
		Resolution:  "Set cluster resource labels",
		Explanation: `Labels make it easier to manage assets and differentiate between clusters and environments, allowing the mapping of computational resources to the wider organisational structure.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseClusterLabelsGoodExamples,
			BadExamples:         terraformUseClusterLabelsBadExamples,
			Links:               terraformUseClusterLabelsLinks,
			RemediationMarkdown: terraformUseClusterLabelsRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.ResourceLabels.Len() == 0 {
				results.Add(
					"Cluster does not use GCE resource labels.",
					cluster.ResourceLabels,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
