package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptionIsEnabled = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0088",
		Provider:    providers2.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-bucket-encryption",
		Summary:     "Unencrypted S3 bucket.",
		Impact:      "The bucket objects could be read if compromised",
		Resolution:  "Configure bucket encryption",
		Explanation: `S3 Buckets should be encrypted to protect the data that is stored within them if access is compromised.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
		},

		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableBucketEncryptionGoodExamples,
			BadExamples:         terraformEnableBucketEncryptionBadExamples,
			Links:               terraformEnableBucketEncryptionLinks,
			RemediationMarkdown: terraformEnableBucketEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableBucketEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableBucketEncryptionBadExamples,
			Links:               cloudFormationEnableBucketEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableBucketEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.Encryption.Enabled.IsFalse() {
				results.Add(
					"Bucket does not have encryption enabled",
					bucket.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&bucket, "Bucket encryption correctly configured")
			}
		}
		return results
	},
)
