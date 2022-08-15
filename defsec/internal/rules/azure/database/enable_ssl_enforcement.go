package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableSslEnforcement = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0020",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "enable-ssl-enforcement",
		Summary:     "SSL should be enforced on database connections where applicable",
		Impact:      "Insecure connections could lead to data loss and other vulnerabilities",
		Resolution:  "Enable SSL enforcement",
		Explanation: `SSL connections should be enforced were available to ensure secure transfer and reduce the risk of compromising data in flight.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableSslEnforcementGoodExamples,
			BadExamples:         terraformEnableSslEnforcementBadExamples,
			Links:               terraformEnableSslEnforcementLinks,
			RemediationMarkdown: terraformEnableSslEnforcementRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.EnableSSLEnforcement.IsFalse() {
				results.Add(
					"Database server does not have enforce SSL.",
					server.EnableSSLEnforcement,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
