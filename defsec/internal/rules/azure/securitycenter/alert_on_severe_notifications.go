package securitycenter

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAlertOnSevereNotifications = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0044",
		Provider:   providers2.AzureProvider,
		Service:    "security-center",
		ShortCode:  "alert-on-severe-notifications",
		Summary:    "Send notification emails for high severity alerts",
		Impact:     "The ability to react to high severity notifications could be delayed",
		Resolution: " Set alert notifications to be on",
		Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident using email and require alerting to be turned on.`,
		Links: []string{
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAlertOnSevereNotificationsGoodExamples,
			BadExamples:         terraformAlertOnSevereNotificationsBadExamples,
			Links:               terraformAlertOnSevereNotificationsLinks,
			RemediationMarkdown: terraformAlertOnSevereNotificationsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, contact := range s.Azure.SecurityCenter.Contacts {
			if contact.IsUnmanaged() {
				continue
			}
			if contact.EnableAlertNotifications.IsFalse() {
				results.Add(
					"Security contact has alert notifications disabled.",
					contact.EnableAlertNotifications,
				)
			} else {
				results.AddPassed(&contact)
			}
		}
		return
	},
)
