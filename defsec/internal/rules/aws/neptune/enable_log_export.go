package neptune

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableLogExport = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0075",
		Provider:    providers2.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-log-export",
		Summary:     "Neptune logs export should be enabled",
		Impact:      "Limited visibility of audit trail for changes to Neptune",
		Resolution:  "Enable export logs",
		Explanation: `Neptune does not have auditing by default. To ensure that you are able to accurately audit the usage of your Neptune instance you should enable export logs.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/auditing.html",
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
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.Logging.Audit.IsFalse() {
				results.Add(
					"Cluster does not have audit logging enabled.",
					cluster.Logging.Audit,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
