package rds

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnablePerformanceInsightsEncryption = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0078",
		Provider:   providers2.AWSProvider,
		Service:    "rds",
		ShortCode:  "enable-performance-insights-encryption",
		Summary:    "Encryption for RDS Performance Insights should be enabled.",
		Impact:     "Data can be read from the RDS Performance Insights if it is compromised",
		Resolution: "Enable encryption for RDS clusters and instances",
		Explanation: `When enabling Performance Insights on an RDS cluster or RDS DB Instance, and encryption key should be provided.

The encryption key specified in ` + "`" + `performance_insights_kms_key_id` + "`" + ` references a KMS ARN`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.htm",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnablePerformanceInsightsEncryptionGoodExamples,
			BadExamples:         terraformEnablePerformanceInsightsEncryptionBadExamples,
			Links:               terraformEnablePerformanceInsightsEncryptionLinks,
			RemediationMarkdown: terraformEnablePerformanceInsightsEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnablePerformanceInsightsEncryptionGoodExamples,
			BadExamples:         cloudFormationEnablePerformanceInsightsEncryptionBadExamples,
			Links:               cloudFormationEnablePerformanceInsightsEncryptionLinks,
			RemediationMarkdown: cloudFormationEnablePerformanceInsightsEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				if instance.IsUnmanaged() {
					continue
				}
				if instance.PerformanceInsights.Enabled.IsFalse() {
					continue
				} else if instance.PerformanceInsights.KMSKeyID.IsEmpty() {
					results.Add(
						"Instance has performance insights enabled without encryption.",
						instance.PerformanceInsights.KMSKeyID,
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
				continue
			} else if instance.PerformanceInsights.KMSKeyID.IsEmpty() {
				results.Add(
					"Instance has performance insights enabled without encryption.",
					instance.PerformanceInsights.KMSKeyID,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)
