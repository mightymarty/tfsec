package container

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0040",
		Provider:    providers2.AzureProvider,
		Service:     "container",
		ShortCode:   "logging",
		Summary:     "Ensure AKS logging to Azure Monitoring is Configured",
		Impact:      "Logging provides valuable information about access and usage",
		Resolution:  "Enable logging for AKS",
		Explanation: `Ensure AKS logging to Azure Monitoring is configured for containers to monitor the performance of workloads.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-onboard",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformLoggingGoodExamples,
			BadExamples:         terraformLoggingBadExamples,
			Links:               terraformLoggingLinks,
			RemediationMarkdown: terraformLoggingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.AddonProfile.OMSAgent.Enabled.IsFalse() {
				results.Add(
					"Cluster does not have logging enabled via OMS Agent.",
					cluster.AddonProfile.OMSAgent.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
