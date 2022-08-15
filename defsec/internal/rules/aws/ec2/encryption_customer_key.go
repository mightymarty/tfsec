package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0027",
		Aliases:     []string{"aws-ebs-encryption-customer-key"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "volume-encryption-customer-key",
		Summary:     "EBS volume encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your EBS volume. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links:       []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformEncryptionCustomerKeyBadExamples,
			Links:               terraformEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, volume := range s.AWS.EC2.Volumes {
			if volume.IsUnmanaged() {
				continue
			}
			if volume.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"EBS volume does not use a customer-managed KMS key.",
					volume.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&volume)
			}
		}
		return
	},
)
