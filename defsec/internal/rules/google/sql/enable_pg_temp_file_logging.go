package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	sql2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/sql"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnablePgTempFileLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0014",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "enable-pg-temp-file-logging",
		Summary:     "Temporary file logging should be enabled for all temporary files.",
		Impact:      "Use of temporary files will not be logged",
		Resolution:  "Enable temporary file logging for all files",
		Explanation: `Temporary files are not logged by default. To log all temporary files, a value of ` + "`" + `0` + "`" + ` should set in the ` + "`" + `log_temp_files` + "`" + ` flag - as all files greater in size than the number of bytes set in this flag will be logged.`,
		Links: []string{
			"https://postgresqlco.nf/doc/en/param/log_temp_files/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnablePgTempFileLoggingGoodExamples,
			BadExamples:         terraformEnablePgTempFileLoggingBadExamples,
			Links:               terraformEnablePgTempFileLoggingLinks,
			RemediationMarkdown: terraformEnablePgTempFileLoggingRemediationMarkdown,
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
			if instance.Settings.Flags.LogTempFileSize.LessThan(0) {
				results.Add(
					"Database instance has temporary file logging disabled.",
					instance.Settings.Flags.LogTempFileSize,
				)
			} else if instance.Settings.Flags.LogTempFileSize.GreaterThan(0) {
				results.Add(
					"Database instance has temporary file logging disabled for files of certain sizes.",
					instance.Settings.Flags.LogTempFileSize,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
