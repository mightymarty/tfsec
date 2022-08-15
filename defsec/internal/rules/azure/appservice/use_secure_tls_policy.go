package appservice

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0006",
		Provider:    providers2.AzureProvider,
		Service:     "appservice",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "Web App uses latest TLS version",
		Impact:      "The minimum TLS version for apps should be TLS1_2",
		Resolution:  "The TLS version being outdated and has known vulnerabilities",
		Explanation: `Use a more recent TLS/SSL policy for the App Service`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Site.MinimumTLSVersion.NotEqualTo("1.2") {
				results.Add(
					"App service does not require a secure TLS version.",
					service.Site.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
