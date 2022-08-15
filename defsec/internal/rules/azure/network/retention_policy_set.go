package network

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckRetentionPolicySet = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0049",
		Provider:   providers2.AzureProvider,
		Service:    "network",
		ShortCode:  "retention-policy-set",
		Summary:    "Retention policy for flow logs should be enabled and set to greater than 90 days",
		Impact:     "Not enabling retention or having short expiry on flow logs could lead to compromise being undetected limiting time for analysis",
		Resolution: "Ensure flow log retention is turned on with an expiry of >90 days",
		Explanation: `Flow logs are the source of truth for all network activity in your cloud environment. 
To enable analysis in security event that was detected late, you need to have the logs available. 
			
Setting an retention policy will help ensure as much information is available for review.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformRetentionPolicySetGoodExamples,
			BadExamples:         terraformRetentionPolicySetBadExamples,
			Links:               terraformRetentionPolicySetLinks,
			RemediationMarkdown: terraformRetentionPolicySetRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, flowLog := range s.Azure.Network.NetworkWatcherFlowLogs {
			if flowLog.IsUnmanaged() {
				continue
			}
			if flowLog.RetentionPolicy.Enabled.IsFalse() {
				results.Add(
					"Flow log does not enable the log retention policy.",
					flowLog.RetentionPolicy.Enabled,
				)
			} else if flowLog.RetentionPolicy.Days.LessThan(90) {
				results.Add(
					"Flow log has a log retention policy of less than 90 days.",
					flowLog.RetentionPolicy.Days,
				)
			} else {
				results.AddPassed(&flowLog)
			}
		}
		return
	},
)
