package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPgLogDisconnections = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0022",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-disconnections",
		Summary:     "Ensure that logging of disconnections is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable disconnection logging.",
		Explanation: `Logging disconnections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-DISCONNECTIONS",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPgLogDisconnectionsGoodExamples,
			BadExamples:         terraformPgLogDisconnectionsBadExamples,
			Links:               terraformPgLogDisconnectionsLinks,
			RemediationMarkdown: terraformPgLogDisconnectionsRemediationMarkdown,
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
			if instance.Settings.Flags.LogDisconnections.IsFalse() {
				results.Add(
					"Database instance is not configured to log disconnections.",
					instance.Settings.Flags.LogDisconnections,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
