package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckLoggingIsEnabled = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0089",
		Provider:    providers2.AWSProvider,
		Service:     "s3",
		ShortCode:   "enable-bucket-logging",
		Summary:     "S3 Bucket does not have logging enabled.",
		Explanation: "Buckets should have logging enabled so that access can be audited.",
		Impact:      "There is no way to determine the access to this bucket",
		Resolution:  "Add a logging block to the resource to enable access logging",
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableBucketLoggingGoodExamples,
			BadExamples:         terraformEnableBucketLoggingBadExamples,
			Links:               terraformEnableBucketLoggingLinks,
			RemediationMarkdown: terraformEnableBucketLoggingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableBucketLoggingGoodExamples,
			BadExamples:         cloudFormationEnableBucketLoggingBadExamples,
			Links:               cloudFormationEnableBucketLoggingLinks,
			RemediationMarkdown: cloudFormationEnableBucketLoggingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if !bucket.Logging.Enabled.IsTrue() && bucket.ACL.NotEqualTo("log-delivery-write") {
				results.Add(
					"Bucket does not have logging enabled",
					bucket.Logging.Enabled,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
