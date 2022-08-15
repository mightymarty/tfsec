package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPostgresConfigurationLogConnections = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0019",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-log-connections",
		Summary:     "Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No visibility of successful connections",
		Resolution:  "Enable connection logging",
		Explanation: `Postgresql can generate logs for successful connections to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPostgresConfigurationLogConnectionsGoodExamples,
			BadExamples:         terraformPostgresConfigurationLogConnectionsBadExamples,
			Links:               terraformPostgresConfigurationLogConnectionsLinks,
			RemediationMarkdown: terraformPostgresConfigurationLogConnectionsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.Config.LogConnections.IsFalse() {
				results.Add(
					"Database server is not configured to log connections.",
					server.Config.LogConnections,
				)
			} else {
				results.AddPassed(&server.Config)
			}
		}
		return
	},
)
