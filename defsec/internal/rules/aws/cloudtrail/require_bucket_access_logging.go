package cloudtrail

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var checkBucketAccessLoggingRequired = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0163",
		Provider:  providers2.AWSProvider,
		Service:   "cloudtrail",
		ShortCode: "require-bucket-access-logging",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"2.6"},
		},
		Summary:    "You should enable bucket access logging on the CloudTrail S3 bucket.",
		Impact:     "There is no way to determine the access to this bucket",
		Resolution: "Enable access logging on the bucket",
		Explanation: `Amazon S3 bucket access logging generates a log that contains access records for each request made to your S3 bucket. An access log record contains details about the request, such as the request type, the resources specified in the request worked, and the time and date the request was processed.

CIS recommends that you enable bucket access logging on the CloudTrail S3 bucket.

By enabling S3 bucket logging on target S3 buckets, you can capture all events that might affect objects in a target bucket. Configuring logs to be placed in a separate bucket enables access to log information, which can be useful in security and incident response workflows.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformBucketAccessLoggingRequiredGoodExamples,
			BadExamples:         terraformBucketAccessLoggingRequiredBadExamples,
			Links:               terraformBucketAccessLoggingRequiredLinks,
			RemediationMarkdown: terraformBucketAccessLoggingRequiredRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationBucketAccessLoggingRequiredGoodExamples,
			BadExamples:         cloudFormationBucketAccessLoggingRequiredBadExamples,
			Links:               cloudFormationBucketAccessLoggingRequiredLinks,
			RemediationMarkdown: cloudFormationBucketAccessLoggingRequiredRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.BucketName.IsNotEmpty() {
				for _, bucket := range s.AWS.S3.Buckets {
					if bucket.Name.EqualTo(trail.BucketName.Value()) {
						if bucket.Logging.Enabled.IsFalse() {
							results.Add("Trail S3 bucket does not have logging enabled", &bucket)
						} else {
							results.AddPassed(&bucket)
						}
					}
				}
			}
		}
		return
	},
)
