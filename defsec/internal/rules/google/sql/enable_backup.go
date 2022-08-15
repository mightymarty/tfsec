package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableBackup = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0024",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "enable-backup",
		Summary:     "Enable automated backups to recover from data-loss",
		Impact:      "No recovery of lost or corrupted data",
		Resolution:  "Enable automated backups",
		Explanation: `Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.`,
		Links: []string{
			"https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableBackupGoodExamples,
			BadExamples:         terraformEnableBackupBadExamples,
			Links:               terraformEnableBackupLinks,
			RemediationMarkdown: terraformEnableBackupRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() || instance.IsReplica.IsTrue() {
				continue
			}
			if instance.Settings.Backups.Enabled.IsFalse() {
				results.Add(
					"Database instance does not have backups enabled.",
					instance.Settings.Backups.Enabled,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
