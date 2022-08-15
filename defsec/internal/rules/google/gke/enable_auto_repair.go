package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAutoRepair = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0063",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-auto-repair",
		Summary:     "Kubernetes should have 'Automatic repair' enabled",
		Impact:      "Failing nodes will require manual repair.",
		Resolution:  "Enable automatic repair",
		Explanation: `Automatic repair will monitor nodes and attempt repair when a node fails multiple subsequent health checks`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAutoRepairGoodExamples,
			BadExamples:         terraformEnableAutoRepairBadExamples,
			Links:               terraformEnableAutoRepairLinks,
			RemediationMarkdown: terraformEnableAutoRepairRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			for _, nodePool := range cluster.NodePools {
				if nodePool.Management.EnableAutoRepair.IsFalse() {
					results.Add(
						"Node pool does not have auto-repair enabled.",
						nodePool.Management.EnableAutoRepair,
					)
				} else {
					results.AddPassed(&nodePool)
				}
			}
		}
		return
	},
)
