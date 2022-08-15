package dynamodb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableRecovery = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0024",
		Provider:   providers2.AWSProvider,
		Service:    "dynamodb",
		ShortCode:  "enable-recovery",
		Summary:    "Point in time recovery should be enabled to protect DynamoDB table",
		Impact:     "Accidental or malicious writes and deletes can't be rolled back",
		Resolution: "Enable point in time recovery",
		Explanation: `DynamoDB tables should be protected against accidentally or malicious write/delete actions by ensuring that there is adequate protection.

By enabling point-in-time-recovery you can restore to a known point in the event of loss of data.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableRecoveryGoodExamples,
			BadExamples:         terraformEnableRecoveryBadExamples,
			Links:               terraformEnableRecoveryLinks,
			RemediationMarkdown: terraformEnableRecoveryRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.DynamoDB.DAXClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.PointInTimeRecovery.IsFalse() {
				results.Add(
					"Point-in-time recovery is not enabled.",
					cluster.PointInTimeRecovery,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		for _, table := range s.AWS.DynamoDB.Tables {
			if table.IsUnmanaged() {
				continue
			}
			if table.PointInTimeRecovery.IsFalse() {
				results.Add(
					"Point-in-time recovery is not enabled.",
					table.PointInTimeRecovery,
				)
			} else {
				results.AddPassed(&table)
			}
		}
		return
	},
)
