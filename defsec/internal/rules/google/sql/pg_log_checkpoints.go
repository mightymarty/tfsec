package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPgLogCheckpoints = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0025",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-checkpoints",
		Summary:     "Ensure that logging of checkpoints is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable checkpoints logging.",
		Explanation: `Logging checkpoints provides useful diagnostic data, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CHECKPOINTS",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPgLogCheckpointsGoodExamples,
			BadExamples:         terraformPgLogCheckpointsBadExamples,
			Links:               terraformPgLogCheckpointsLinks,
			RemediationMarkdown: terraformPgLogCheckpointsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql2.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogCheckpoints.IsFalse() {
				results.Add(
					"Database instance is not configured to log checkpoints.",
					instance.Settings.Flags.LogCheckpoints,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
