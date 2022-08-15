package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckKubernetesSurgeUpgrades = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0005",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "surge-upgrades-not-enabled",
		Summary:     "The Kubernetes cluster does not enable surge upgrades",
		Impact:      "Upgrades may influence availability of your Kubernetes cluster",
		Resolution:  "Enable surge upgrades in your Kubernetes cluster",
		Explanation: `While upgrading your cluster, workloads will temporarily be moved to new nodes. A small cost will follow, but as a bonus, you won't experience downtime.`,
		Links: []string{
			"https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/#surge-upgrades",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformKubernetesClusterSurgeUpgradesGoodExamples,
			BadExamples:         terraformKubernetesClusterSurgeUpgradesBadExamples,
			Links:               terraformKubernetesClusterSurgeUpgradeLinks,
			RemediationMarkdown: terraformKubernetesClusterSurgeUpgradesMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, kc := range s.DigitalOcean.Compute.KubernetesClusters {
			if kc.IsUnmanaged() {
				continue
			}
			if kc.SurgeUpgrade.IsFalse() {
				results.Add(
					"Surge upgrades are disabled in your Kubernetes cluster. Please enable this feature.",
					kc.SurgeUpgrade,
				)
			} else {
				results.AddPassed(&kc)
			}
		}
		return
	},
)
