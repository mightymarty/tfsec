package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableTableEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0121",
		Provider:    providers2.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-table-encryption",
		Summary:     "SAM Simple table must have server side encryption enabled.",
		Impact:      "Data stored in the table that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable server side encryption",
		Explanation: `Encryption should be enabled at all available levels to ensure that data is protected if compromised.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html#sam-simpletable-ssespecification",
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableTableEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableTableEncryptionBadExamples,
			Links:               cloudFormationEnableTableEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableTableEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, table := range s.AWS.SAM.SimpleTables {
			if table.SSESpecification.Enabled.IsFalse() {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					table.SSESpecification.Enabled,
				)
			} else {
				results.AddPassed(&table)
			}
		}
		return
	},
)
