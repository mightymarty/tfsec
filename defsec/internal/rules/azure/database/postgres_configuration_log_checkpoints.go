package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPostgresConfigurationLogCheckpoints = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0024",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-log-checkpoints",
		Summary:     "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No error and query logs generated on checkpoint",
		Resolution:  "Enable checkpoint logging",
		Explanation: `Postgresql can generate logs for checkpoints to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPostgresConfigurationLogCheckpointsGoodExamples,
			BadExamples:         terraformPostgresConfigurationLogCheckpointsBadExamples,
			Links:               terraformPostgresConfigurationLogCheckpointsLinks,
			RemediationMarkdown: terraformPostgresConfigurationLogCheckpointsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.IsUnmanaged() {
				continue
			}
			if server.Config.LogCheckpoints.IsFalse() {
				results.Add(
					"Database server is not configured to log checkpoints.",
					server.Config.LogCheckpoints,
				)
			} else {
				results.AddPassed(&server.Config)
			}
		}
		return
	},
)
