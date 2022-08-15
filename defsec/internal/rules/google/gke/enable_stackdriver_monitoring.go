package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableStackdriverMonitoring = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0052",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-stackdriver-monitoring",
		Summary:     "Stackdriver Monitoring should be enabled",
		Impact:      "Visibility will be reduced",
		Resolution:  "Enable StackDriver monitoring",
		Explanation: `StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableStackdriverMonitoringGoodExamples,
			BadExamples:         terraformEnableStackdriverMonitoringBadExamples,
			Links:               terraformEnableStackdriverMonitoringLinks,
			RemediationMarkdown: terraformEnableStackdriverMonitoringRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.MonitoringService.NotEqualTo("monitoring.googleapis.com/kubernetes") {
				results.Add(
					"Cluster does not use the monitoring.googleapis.com/kubernetes StackDriver monitoring service.",
					cluster.MonitoringService,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
