package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoCrossDbOwnershipChaining = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0019",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-cross-db-ownership-chaining",
		Summary:     "Cross-database ownership chaining should be disabled",
		Impact:      "Unintended access to sensitive data",
		Resolution:  "Disable cross database ownership chaining",
		Explanation: `Cross-database ownership chaining, also known as cross-database chaining, is a security feature of SQL Server that allows users of databases access to other databases besides the one they are currently using.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoCrossDbOwnershipChainingGoodExamples,
			BadExamples:         terraformNoCrossDbOwnershipChainingBadExamples,
			Links:               terraformNoCrossDbOwnershipChainingLinks,
			RemediationMarkdown: terraformNoCrossDbOwnershipChainingRemediationMarkdown,
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
			if instance.Settings.Flags.CrossDBOwnershipChaining.IsTrue() {
				results.Add(
					"Database instance has cross database ownership chaining enabled.",
					instance.Settings.Flags.CrossDBOwnershipChaining,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
