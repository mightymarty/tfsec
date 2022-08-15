package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0026",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "secure-tls-policy",
		Summary:     "Databases should have the minimum TLS set for connections",
		Impact:      "Outdated TLS policies increase exposure to known issues",
		Resolution:  "Use the most modern TLS policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSecureTlsPolicyGoodExamples,
			BadExamples:         terraformSecureTlsPolicyBadExamples,
			Links:               terraformSecureTlsPolicyLinks,
			RemediationMarkdown: terraformSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.MinimumTLSVersion.NotEqualTo("1.2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.MinimumTLSVersion.NotEqualTo("TLS1_2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.MinimumTLSVersion.NotEqualTo("TLS1_2") {
				results.Add(
					"Database server does not require a secure TLS version.",
					server.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
