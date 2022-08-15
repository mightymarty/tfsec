package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoContainedDbAuth = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0023",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-contained-db-auth",
		Summary:     "Contained database authentication should be disabled",
		Impact:      "Access can be granted without knowledge of the database administrator",
		Resolution:  "Disable contained database authentication",
		Explanation: `Users with ALTER permissions on users can grant access to a contained database without the knowledge of an administrator`,
		Links: []string{
			"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoContainedDbAuthGoodExamples,
			BadExamples:         terraformNoContainedDbAuthBadExamples,
			Links:               terraformNoContainedDbAuthLinks,
			RemediationMarkdown: terraformNoContainedDbAuthRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql2.DatabaseFamilySQLServer {
				continue
			}
			if instance.Settings.Flags.ContainedDatabaseAuthentication.IsTrue() {
				results.Add(
					"Database instance has contained database authentication enabled.",
					instance.Settings.Flags.ContainedDatabaseAuthentication,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
