package ecs

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableContainerInsight = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0034",
		Provider:    providers2.AWSProvider,
		Service:     "ecs",
		ShortCode:   "enable-container-insight",
		Summary:     "ECS clusters should have container insights enabled",
		Impact:      "Not all metrics and logs may be gathered for containers when Container Insights isn't enabled",
		Resolution:  "Enable Container Insights",
		Explanation: `Cloudwatch Container Insights provide more metrics and logs for container based applications and micro services.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/ContainerInsights.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableContainerInsightGoodExamples,
			BadExamples:         terraformEnableContainerInsightBadExamples,
			Links:               terraformEnableContainerInsightLinks,
			RemediationMarkdown: terraformEnableContainerInsightRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableContainerInsightGoodExamples,
			BadExamples:         cloudFormationEnableContainerInsightBadExamples,
			Links:               cloudFormationEnableContainerInsightLinks,
			RemediationMarkdown: cloudFormationEnableContainerInsightRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.ECS.Clusters {
			if cluster.Settings.ContainerInsightsEnabled.IsFalse() {
				results.Add(
					"Cluster does not have container insights enabled.",
					cluster.Settings.ContainerInsightsEnabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
