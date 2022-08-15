package ssm

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	ssm2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ssm"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSecretUseCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0098",
		Provider:    providers2.AWSProvider,
		Service:     "ssm",
		ShortCode:   "secret-use-customer-key",
		Summary:     "Secrets Manager should use customer managed keys",
		Impact:      "Using AWS managed keys reduces the flexibility and control over the encryption key",
		Resolution:  "Use customer managed keys",
		Explanation: `Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.`,
		Links: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSecretUseCustomerKeyGoodExamples,
			BadExamples:         terraformSecretUseCustomerKeyBadExamples,
			Links:               terraformSecretUseCustomerKeyLinks,
			RemediationMarkdown: terraformSecretUseCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationSecretUseCustomerKeyGoodExamples,
			BadExamples:         cloudFormationSecretUseCustomerKeyBadExamples,
			Links:               cloudFormationSecretUseCustomerKeyLinks,
			RemediationMarkdown: cloudFormationSecretUseCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, secret := range s.AWS.SSM.Secrets {
			if secret.KMSKeyID.IsEmpty() {
				results.Add(
					"Secret is not encrypted with a customer managed key.",
					secret.KMSKeyID,
				)
			} else if secret.KMSKeyID.EqualTo(ssm2.DefaultKMSKeyID) {
				results.Add(
					"Secret explicitly uses the default key.",
					secret.KMSKeyID,
				)
			} else {
				results.AddPassed(&secret)
			}
		}
		return
	},
)
