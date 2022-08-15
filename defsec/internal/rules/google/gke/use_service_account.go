package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseServiceAccount = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0050",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-service-account",
		Summary:     "Checks for service account defined for GKE nodes",
		Impact:      "Service accounts with wide permissions can increase the risk of compromise",
		Resolution:  "Use limited permissions for service accounts to be effective",
		Explanation: `You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseServiceAccountGoodExamples,
			BadExamples:         terraformUseServiceAccountBadExamples,
			Links:               terraformUseServiceAccountLinks,
			RemediationMarkdown: terraformUseServiceAccountRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsManaged() {
				if cluster.RemoveDefaultNodePool.IsFalse() {
					if cluster.NodeConfig.ServiceAccount.IsEmpty() {
						results.Add(
							"Cluster does not override the default service account.",
							cluster.NodeConfig.ServiceAccount,
						)
					}
				} else {
					results.AddPassed(&cluster)
				}
			}
			for _, pool := range cluster.NodePools {
				if pool.NodeConfig.ServiceAccount.IsEmpty() {
					results.Add(
						"Node pool does not override the default service account.",
						pool.NodeConfig.ServiceAccount,
					)
				} else {
					results.AddPassed(&pool)
				}
			}
		}
		return
	},
)
