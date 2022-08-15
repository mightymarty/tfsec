package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAutoUpgrade = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0008",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "kubernetes-auto-upgrades-not-enabled",
		Summary:     "Kubernetes clusters should be auto-upgraded to ensure that they always contain the latest security patches.",
		Impact:      "Not running the latest security patches on your Kubernetes cluster can make it a target for penetration.",
		Resolution:  "Set maintenance policy deterministically when auto upgrades are enabled",
		Explanation: ``,
		Links: []string{
			"https://docs.digitalocean.com/products/kubernetes/resources/best-practices/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformKubernetesClusterAutoUpgradeGoodExample,
			BadExamples:         terraformKubernetesClusterAutoUpgradeBadExample,
			Links:               terraformKubernetesClusterAutoUpgradeLinks,
			RemediationMarkdown: terraformKubernetesAutoUpgradeMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, kc := range s.DigitalOcean.Compute.KubernetesClusters {
			if kc.IsUnmanaged() {
				continue
			}
			if kc.AutoUpgrade.IsFalse() {
				results.Add(
					"Kubernetes Cluster does not enable auto upgrades enabled",
					kc.AutoUpgrade,
				)
			} else {
				results.AddPassed(&kc)
			}
		}
		return
	},
)
