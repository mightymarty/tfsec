package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckBucketsHavePublicAccessBlocks = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0094",
		Provider:    providers2.AWSProvider,
		Service:     "s3",
		ShortCode:   "specify-public-access-block",
		Summary:     "S3 buckets should each define an aws_s3_bucket_public_access_block",
		Explanation: `The "block public access" settings in S3 override individual policies that apply to a given bucket, meaning that all public access can be controlled in one central types for that bucket. It is therefore good practice to define these settings for each bucket in order to clearly define the public access that can be allowed for it.`,
		Impact:      "Public access policies may be applied to sensitive data buckets",
		Resolution:  "Define a aws_s3_bucket_public_access_block for the given bucket to control public access policies",
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSpecifyPublicAccessBlockGoodExamples,
			BadExamples:         terraformSpecifyPublicAccessBlockBadExamples,
			Links:               terraformSpecifyPublicAccessBlockLinks,
			RemediationMarkdown: terraformSpecifyPublicAccessBlockRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationSpecifyPublicAccessBlockGoodExamples,
			BadExamples:         cloudFormationSpecifyPublicAccessBlockBadExamples,
			Links:               cloudFormationSpecifyPublicAccessBlockLinks,
			RemediationMarkdown: cloudFormationSpecifyPublicAccessBlockRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add(
					"Bucket does not have a corresponding public access block.",
					&bucket,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
