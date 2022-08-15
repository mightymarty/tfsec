package sns

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckTopicEncryptionUsesCMK = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0136",
		ShortCode:   "topic-encryption-use-cmk",
		Summary:     "SNS topic not encrypted with CMK.",
		Explanation: `Topics should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular key management.`,
		Impact:      "Key management very limited when using default keys.",
		Resolution:  "Use a CMK for SNS Topic encryption",
		Provider:    providers2.AWSProvider,
		Service:     "sns",
		Links: []string{
			"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
		},
		Severity: severity2.High,
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformTopicEncryptionUsesCMKGoodExamples,
			BadExamples:         terraformTopicEncryptionUsesCMKBadExamples,
			Links:               terraformTopicEncryptionUsesCMKLinks,
			RemediationMarkdown: terraformTopicEncryptionUsesCMKRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationTopicEncryptionUsesCMKGoodExamples,
			BadExamples:         cloudFormationTopicEncryptionUsesCMKBadExamples,
			Links:               cloudFormationTopicEncryptionUsesCMKLinks,
			RemediationMarkdown: cloudFormationTopicEncryptionUsesCMKRemediationMarkdown,
		},
		CustomChecks: scan2.CustomChecks{},
		RegoPackage:  "",
	},
	func(s *state2.State) (results scan2.Results) {
		for _, topic := range s.AWS.SNS.Topics {
			if topic.Encryption.KMSKeyID.EqualTo("alias/aws/sns") {
				results.Add(
					"Topic encryption does not use a customer managed key.",
					topic.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&topic)
			}
		}
		return
	},
)
