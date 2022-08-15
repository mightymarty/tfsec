package monitor

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckActivityLogRetentionSet = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0031",
		Provider:    providers2.AzureProvider,
		Service:     "monitor",
		ShortCode:   "activity-log-retention-set",
		Summary:     "Ensure the activity retention log is set to at least a year",
		Impact:      "Short life activity logs can lead to missing records when investigating a breach",
		Resolution:  "Set a retention period that will allow for delayed investigation",
		Explanation: `The average time to detect a breach is up to 210 days, to ensure that all the information required for an effective investigation is available, the retention period should allow for delayed starts to investigating.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformActivityLogRetentionSetGoodExamples,
			BadExamples:         terraformActivityLogRetentionSetBadExamples,
			Links:               terraformActivityLogRetentionSetLinks,
			RemediationMarkdown: terraformActivityLogRetentionSetRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, profile := range s.Azure.Monitor.LogProfiles {
			if profile.IsUnmanaged() {
				continue
			}
			if profile.RetentionPolicy.Enabled.IsFalse() {
				results.Add(
					"Profile does not enable the log retention policy.",
					profile.RetentionPolicy.Enabled,
				)
			} else if profile.RetentionPolicy.Days.LessThan(365) {
				results.Add(
					"Profile has a log retention policy of less than 1 year.",
					profile.RetentionPolicy.Days,
				)
			} else {
				results.AddPassed(&profile)
			}
		}
		return
	},
)
