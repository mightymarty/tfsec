package ecr

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	ecr2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ecr"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckRepositoryCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0033",
		Provider:    providers2.AWSProvider,
		Service:     "ecr",
		ShortCode:   "repository-customer-key",
		Summary:     "ECR Repository should use customer managed keys to allow more control",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Use customer managed keys",
		Explanation: `Images in the ECR repository are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformRepositoryCustomerKeyGoodExamples,
			BadExamples:         terraformRepositoryCustomerKeyBadExamples,
			Links:               terraformRepositoryCustomerKeyLinks,
			RemediationMarkdown: terraformRepositoryCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationRepositoryCustomerKeyGoodExamples,
			BadExamples:         cloudFormationRepositoryCustomerKeyBadExamples,
			Links:               cloudFormationRepositoryCustomerKeyLinks,
			RemediationMarkdown: cloudFormationRepositoryCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.Encryption.Type.NotEqualTo(ecr2.EncryptionTypeKMS) {
				results.Add(
					"Repository is not encrypted using KMS.",
					repo.Encryption.Type,
				)
			} else if repo.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Repository encryption does not use a customer managed KMS key.",
					repo.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)
