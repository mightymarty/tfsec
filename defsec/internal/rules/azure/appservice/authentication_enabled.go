package appservice

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAuthenticationEnabled = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0003",
		Provider:    providers2.AzureProvider,
		Service:     "appservice",
		ShortCode:   "authentication-enabled",
		Summary:     "App Service authentication is activated",
		Impact:      "Anonymous HTTP requests will be accepted",
		Resolution:  "Enable authentication to prevent anonymous request being accepted",
		Explanation: `Enabling authentication ensures that all communications in the application are authenticated. The auth_settings block needs to be filled out with the appropriate auth backend settings`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAuthenticationEnabledGoodExamples,
			BadExamples:         terraformAuthenticationEnabledBadExamples,
			Links:               terraformAuthenticationEnabledLinks,
			RemediationMarkdown: terraformAuthenticationEnabledRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Authentication.Enabled.IsFalse() {
				results.Add(
					"App service does not have authentication enabled.",
					service.Authentication.Enabled,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
