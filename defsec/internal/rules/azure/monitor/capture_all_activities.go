package monitor

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	monitor2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/monitor"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckCaptureAllActivities = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0033",
		Provider:    providers2.AzureProvider,
		Service:     "monitor",
		ShortCode:   "capture-all-activities",
		Summary:     "Ensure log profile captures all activities",
		Impact:      "Log profile must capture all activity to be able to ensure that all relevant information possible is available for an investigation",
		Resolution:  "Configure log profile to capture all activities",
		Explanation: `Log profiles should capture all categories to ensure that all events are logged`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
			"https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformCaptureAllActivitiesGoodExamples,
			BadExamples:         terraformCaptureAllActivitiesBadExamples,
			Links:               terraformCaptureAllActivitiesLinks,
			RemediationMarkdown: terraformCaptureAllActivitiesRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		required := []string{
			"Action", "Write", "Delete",
		}
		for _, profile := range s.Azure.Monitor.LogProfiles {
			if profile.IsUnmanaged() {
				continue
			}
			var failed bool
			for _, cat := range required {
				if !hasCategory(profile, cat) {
					failed = true
					results.Add(
						fmt.Sprintf("Log profile does not require the '%s' category.", cat),
						&profile,
					)
				}
			}

			if !failed {
				results.AddPassed(&profile)
			}
		}
		return
	},
)

func hasCategory(profile monitor2.LogProfile, cgry string) bool {
	for _, category := range profile.Categories {
		if category.EqualTo(cgry) {
			return true
		}
	}
	return false
}
