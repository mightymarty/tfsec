package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPgLogLockWaits = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0020",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-lock-waits",
		Summary:     "Ensure that logging of lock waits is enabled.",
		Impact:      "Issues leading to denial of service may not be identified.",
		Resolution:  "Enable lock wait logging.",
		Explanation: `Lock waits are often an indication of poor performance and often an indicator of a potential denial of service vulnerability, therefore occurrences should be logged for analysis.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-LOCK-WAITS",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPgLogLockWaitsGoodExamples,
			BadExamples:         terraformPgLogLockWaitsBadExamples,
			Links:               terraformPgLogLockWaitsLinks,
			RemediationMarkdown: terraformPgLogLockWaitsRemediationMarkdown,
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
			if instance.Settings.Flags.LogLockWaits.IsFalse() {
				results.Add(
					"Database instance is not configured to log lock waits.",
					instance.Settings.Flags.LogLockWaits,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
