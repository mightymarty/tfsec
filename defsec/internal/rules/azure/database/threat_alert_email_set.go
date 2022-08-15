package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckThreatAlertEmailSet = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0018",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "threat-alert-email-set",
		Summary:     "At least one email address is set for threat alerts",
		Impact:      "Nobody will be prompty alerted in the case of a threat being detected",
		Resolution:  "Provide at least one email address for threat alerts",
		Explanation: `SQL Server sends alerts for threat detection via email, if there are no email addresses set then mitigation will be delayed.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformThreatAlertEmailSetGoodExamples,
			BadExamples:         terraformThreatAlertEmailSetBadExamples,
			Links:               terraformThreatAlertEmailSetLinks,
			RemediationMarkdown: terraformThreatAlertEmailSetRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.SecurityAlertPolicies {
				if len(policy.EmailAddresses) == 0 {
					results.Add(
						"Security alert policy does not include any email addresses for notification.",
						&policy,
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
