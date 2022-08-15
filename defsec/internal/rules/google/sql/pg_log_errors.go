package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPgLogErrors = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0018",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-errors",
		Summary:     "Ensure that Postgres errors are logged",
		Impact:      "Loss of error logging",
		Resolution:  "Set the minimum log severity to at least ERROR",
		Explanation: `Setting the minimum log severity too high will cause errors not to be logged`,
		Links: []string{
			"https://postgresqlco.nf/doc/en/param/log_min_messages/",
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPgLogErrorsGoodExamples,
			BadExamples:         terraformPgLogErrorsBadExamples,
			Links:               terraformPgLogErrorsLinks,
			RemediationMarkdown: terraformPgLogErrorsRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql2.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogMinMessages.IsOneOf("FATAL", "PANIC", "LOG") {
				results.Add(
					"Database instance is not configured to log errors.",
					instance.Settings.Flags.LogMinMessages,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
