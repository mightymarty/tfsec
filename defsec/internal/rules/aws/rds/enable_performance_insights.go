package rds

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnablePerformanceInsights = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0133",
		Provider:   providers2.AWSProvider,
		Service:    "rds",
		ShortCode:  "enable-performance-insights",
		Summary:    "Enable Performance Insights to detect potential problems",
		Impact:     "Without adequate monitoring, performance related issues may go unreported and potentially lead to compromise.",
		Resolution: "Enable performance insights",
		Explanation: `Enabling Performance insights allows for greater depth in monitoring data.
		
For example, information about active sessions could help diagose a compromise or assist in the investigation`,
		Links: []string{
			"https://aws.amazon.com/rds/performance-insights/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnablePerformanceInsightsGoodExamples,
			BadExamples:         terraformEnablePerformanceInsightsBadExamples,
			Links:               terraformEnablePerformanceInsightsLinks,
			RemediationMarkdown: terraformEnablePerformanceInsightsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnablePerformanceInsightsGoodExamples,
			BadExamples:         cloudFormationEnablePerformanceInsightsBadExamples,
			Links:               cloudFormationEnablePerformanceInsightsLinks,
			RemediationMarkdown: cloudFormationEnablePerformanceInsightsRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				if instance.IsUnmanaged() {
					continue
				}
				if instance.PerformanceInsights.Enabled.IsFalse() {
					results.Add(
						"Instance does not have performance insights enabled.",
						instance.PerformanceInsights.Enabled,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.PerformanceInsights.Enabled.IsFalse() {
				results.Add(
					"Instance does not have performance insights enabled.",
					instance.PerformanceInsights.Enabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)
