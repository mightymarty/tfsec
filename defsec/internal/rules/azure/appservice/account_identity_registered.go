package appservice

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAccountIdentityRegistered = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0002",
		Provider:    providers2.AzureProvider,
		Service:     "appservice",
		ShortCode:   "account-identity-registered",
		Summary:     "Web App has registration with AD enabled",
		Impact:      "Interaction between services can't easily be achieved without username/password",
		Resolution:  "Register the app identity with AD",
		Explanation: `Registering the identity used by an App with AD allows it to interact with other services without using username and password`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAccountIdentityRegisteredGoodExamples,
			BadExamples:         terraformAccountIdentityRegisteredBadExamples,
			Links:               terraformAccountIdentityRegisteredLinks,
			RemediationMarkdown: terraformAccountIdentityRegisteredRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Identity.Type.IsEmpty() {
				results.Add(
					"App service does not have an identity type.",
					service.Identity.Type,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
