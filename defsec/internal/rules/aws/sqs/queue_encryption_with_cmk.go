package sqs

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckQueueEncryptionUsesCMK = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0135",
		Provider:    providers2.AWSProvider,
		Service:     "sqs",
		ShortCode:   "queue-encryption-use-cmk",
		Summary:     "SQS queue should be encrypted with a CMK.",
		Impact:      "The SQS queue messages could be read if compromised. Key management is very limited when using default keys.",
		Resolution:  "Encrypt SQS Queue with a customer-managed key",
		Explanation: `Queues should be encrypted with customer managed KMS keys and not default AWS managed keys, in order to allow granular control over access to specific queues.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformQueueEncryptionUsesCMKGoodExamples,
			BadExamples:         terraformQueueEncryptionUsesCMKBadExamples,
			Links:               terraformQueueEncryptionUsesCMKLinks,
			RemediationMarkdown: terraformQueueEncryptionUsesCMKRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationQueueEncryptionUsesCMKGoodExamples,
			BadExamples:         cloudFormationQueueEncryptionUsesCMKBadExamples,
			Links:               cloudFormationQueueEncryptionUsesCMKLinks,
			RemediationMarkdown: cloudFormationQueueEncryptionUsesCMKRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, queue := range s.AWS.SQS.Queues {
			if queue.IsUnmanaged() {
				continue
			}
			if queue.Encryption.KMSKeyID.EqualTo("alias/aws/sqs") {
				results.Add(
					"Queue is not encrypted with a customer managed key.",
					queue.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&queue)
			}
		}
		return
	},
)
