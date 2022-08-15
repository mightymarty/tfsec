package appservice

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckRequireClientCert = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0001",
		Provider:    providers2.AzureProvider,
		Service:     "appservice",
		ShortCode:   "require-client-cert",
		Summary:     "Web App accepts incoming client certificate",
		Impact:      "Mutual TLS is not being used",
		Resolution:  "Enable incoming certificates for clients",
		Explanation: `The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformRequireClientCertGoodExamples,
			BadExamples:         terraformRequireClientCertBadExamples,
			Links:               terraformRequireClientCertLinks,
			RemediationMarkdown: terraformRequireClientCertRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.IsUnmanaged() {
				continue
			}
			if service.EnableClientCert.IsFalse() {
				results.Add(
					"App service does not have client certificates enabled.",
					service.EnableClientCert,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
