package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAutoUpgrade = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0058",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-auto-upgrade",
		Summary:     "Kubernetes should have 'Automatic upgrade' enabled",
		Impact:      "Nodes will need the cluster master version manually updating",
		Resolution:  "Enable automatic upgrades",
		Explanation: `Automatic updates keep nodes updated with the latest cluster master version.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAutoUpgradeGoodExamples,
			BadExamples:         terraformEnableAutoUpgradeBadExamples,
			Links:               terraformEnableAutoUpgradeLinks,
			RemediationMarkdown: terraformEnableAutoUpgradeRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			for _, nodePool := range cluster.NodePools {
				if nodePool.Management.EnableAutoUpgrade.IsFalse() {
					results.Add(
						"Node pool does not have auto-upgraade enabled.",
						nodePool.Management.EnableAutoUpgrade,
					)
				} else {
					results.AddPassed(&nodePool)
				}

			}
		}
		return
	},
)
