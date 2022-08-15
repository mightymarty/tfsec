package securitycenter

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSetRequiredContactDetails = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0046",
		Provider:   providers2.AzureProvider,
		Service:    "security-center",
		ShortCode:  "set-required-contact-details",
		Summary:    "The required contact details should be set for security center",
		Impact:     "Without a telephone number set, Azure support can't contact",
		Resolution: "Set a telephone number for security center contact",
		Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.`,
		Links: []string{
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSetRequiredContactDetailsGoodExamples,
			BadExamples:         terraformSetRequiredContactDetailsBadExamples,
			Links:               terraformSetRequiredContactDetailsLinks,
			RemediationMarkdown: terraformSetRequiredContactDetailsRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, contact := range s.Azure.SecurityCenter.Contacts {
			if contact.IsUnmanaged() {
				continue
			}
			if contact.Phone.IsEmpty() {
				results.Add(
					"Security contact does not have a phone number listed.",
					contact.Phone,
				)
			} else {
				results.AddPassed(&contact)
			}
		}
		return
	},
)
