package documentdb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	documentdb2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/documentdb"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableLogExport = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0020",
		Provider:    providers2.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-log-export",
		Summary:     "DocumentDB logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to the DocumentDB",
		Resolution:  "Enable export logs",
		Explanation: `Document DB does not have auditing by default. To ensure that you are able to accurately audit the usage of your DocumentDB cluster you should enable export logs.`,
		Links: []string{
			"https://docs.aws.amazon.com/documentdb/latest/developerguide/event-auditing.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableLogExportGoodExamples,
			BadExamples:         terraformEnableLogExportBadExamples,
			Links:               terraformEnableLogExportLinks,
			RemediationMarkdown: terraformEnableLogExportRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableLogExportGoodExamples,
			BadExamples:         cloudFormationEnableLogExportBadExamples,
			Links:               cloudFormationEnableLogExportLinks,
			RemediationMarkdown: cloudFormationEnableLogExportRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			var hasAudit bool
			var hasProfiler bool

			for _, log := range cluster.EnabledLogExports {
				if log.EqualTo(documentdb2.LogExportAudit) {
					hasAudit = true
				}
				if log.EqualTo(documentdb2.LogExportProfiler) {
					hasProfiler = true
				}
			}
			if !hasAudit && !hasProfiler {
				results.Add(
					"Neither CloudWatch audit nor profiler log exports are enabled.",
					&cluster,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
