package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckThreatAlertEmailToOwner = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0023",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "threat-alert-email-to-owner",
		Summary:     "Security threat alerts go to subcription owners and co-administrators",
		Impact:      "Administrators and subscription owners may have a delayed response",
		Resolution:  "Enable email to subscription owners",
		Explanation: `Subscription owners should be notified when there are security alerts. By ensuring the administrators of the account have been notified they can quickly assist in any required remediation`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformThreatAlertEmailToOwnerGoodExamples,
			BadExamples:         terraformThreatAlertEmailToOwnerBadExamples,
			Links:               terraformThreatAlertEmailToOwnerLinks,
			RemediationMarkdown: terraformThreatAlertEmailToOwnerRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.SecurityAlertPolicies {
				if policy.EmailAccountAdmins.IsFalse() {
					results.Add(
						"Security alert policy does not alert account admins.",
						policy.EmailAccountAdmins,
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
