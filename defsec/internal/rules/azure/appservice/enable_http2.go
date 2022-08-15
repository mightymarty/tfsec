package appservice

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableHttp2 = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0005",
		Provider:    providers2.AzureProvider,
		Service:     "appservice",
		ShortCode:   "enable-http2",
		Summary:     "Web App uses the latest HTTP version",
		Impact:      "Outdated versions of HTTP has security vulnerabilities",
		Resolution:  "Use the latest version of HTTP",
		Explanation: `Use the latest version of HTTP to ensure you are benefiting from security fixes`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableHttp2GoodExamples,
			BadExamples:         terraformEnableHttp2BadExamples,
			Links:               terraformEnableHttp2Links,
			RemediationMarkdown: terraformEnableHttp2RemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.Site.EnableHTTP2.IsFalse() {
				results.Add(
					"App service does not have HTTP/2 enabled.",
					service.Site.EnableHTTP2,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
