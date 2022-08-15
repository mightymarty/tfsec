package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0132",
		Provider:    providers2.AWSProvider,
		Service:     "s3",
		ShortCode:   "encryption-customer-key",
		Summary:     "S3 encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your S3 buckets. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformCheckEncryptionCustomerKeyBadExamples,
			Links:               terraformCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationCheckEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {

			if bucket.ACL != nil && bucket.ACL.EqualTo("log-delivery-write", types.IgnoreCase) {
				// Log buckets don't support non AES256 encryption - this rule doesn't apply here
				// https://aws.amazon.com/premiumsupport/knowledge-center/s3-server-access-log-not-delivered/
				continue
			}
			if bucket.Encryption.KMSKeyId.IsEmpty() {
				results.Add(
					"Bucket does not encrypt data with a customer managed key.",
					&bucket.Encryption,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
