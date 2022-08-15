package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckMysqlNoLocalInfile = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0026",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "mysql-no-local-infile",
		Summary:     "Disable local_infile setting in MySQL",
		Impact:      "Arbitrary files read by attackers when combined with a SQL injection vulnerability.",
		Resolution:  "Disable the local infile setting",
		Explanation: `Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.`,
		Links: []string{
			"https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformMysqlNoLocalInfileGoodExamples,
			BadExamples:         terraformMysqlNoLocalInfileBadExamples,
			Links:               terraformMysqlNoLocalInfileLinks,
			RemediationMarkdown: terraformMysqlNoLocalInfileRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql2.DatabaseFamilyMySQL {
				continue
			}
			if instance.Settings.Flags.LocalInFile.IsTrue() {
				results.Add(
					"Database instance has local file read access enabled.",
					instance.Settings.Flags.LocalInFile,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
