package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckRetentionPeriodSet = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0025",
		Provider:   providers2.AzureProvider,
		Service:    "database",
		ShortCode:  "retention-period-set",
		Summary:    "Database auditing rentention period should be longer than 90 days",
		Impact:     "Short logging retention could result in missing valuable historical information",
		Resolution: "Set retention periods of database auditing to greater than 90 days",
		Explanation: `When Auditing is configured for a SQL database, if the retention period is not set, the retention will be unlimited.

If the retention period is to be explicitly set, it should be set for no less than 90 days.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformRetentionPeriodSetGoodExamples,
			BadExamples:         terraformRetentionPeriodSetBadExamples,
			Links:               terraformRetentionPeriodSetLinks,
			RemediationMarkdown: terraformRetentionPeriodSetRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.ExtendedAuditingPolicies {
				if policy.RetentionInDays.LessThan(90) && policy.RetentionInDays.NotEqualTo(0) {
					results.Add(
						"Server has a retention period of less than 90 days.",
						policy.RetentionInDays,
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
