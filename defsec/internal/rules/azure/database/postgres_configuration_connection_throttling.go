package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPostgresConfigurationLogConnectionThrottling = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0021",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-connection-throttling",
		Summary:     "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No log information to help diagnosing connection contention issues",
		Resolution:  "Enable connection throttling logging",
		Explanation: `Postgresql can generate logs for connection throttling to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPostgresConfigurationConnectionThrottlingGoodExamples,
			BadExamples:         terraformPostgresConfigurationConnectionThrottlingBadExamples,
			Links:               terraformPostgresConfigurationConnectionThrottlingLinks,
			RemediationMarkdown: terraformPostgresConfigurationConnectionThrottlingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.Config.ConnectionThrottling.IsFalse() {
				results.Add(
					"Database server is not configured to throttle connections.",
					server.Config.ConnectionThrottling,
				)
			} else {
				results.AddPassed(&server.Config)
			}
		}
		return
	},
)
