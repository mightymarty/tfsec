package s3

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckForPublicACL = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0092",
		Provider:  providers2.AWSProvider,
		Service:   "s3",
		ShortCode: "no-public-access-with-acl",
		Summary:   "S3 Buckets not publicly accessible through ACL.",
		Explanation: `
Buckets should not have ACLs that allow public access
`,
		Impact:     "Public access to the bucket can lead to data leakage",
		Resolution: "Don't use canned ACLs or switch to private acl",

		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessWithAclGoodExamples,
			BadExamples:         terraformNoPublicAccessWithAclBadExamples,
			Links:               terraformNoPublicAccessWithAclLinks,
			RemediationMarkdown: terraformNoPublicAccessWithAclRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessWithAclGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessWithAclBadExamples,
			Links:               cloudFormationNoPublicAccessWithAclLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessWithAclRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.HasPublicExposureACL() {
				if bucket.ACL.EqualTo("authenticated-read") {
					results.Add(
						"Bucket is exposed to all AWS accounts via ACL.",
						bucket.ACL,
					)
				} else {
					results.Add(
						fmt.Sprintf("Bucket has a public ACL: '%s'.", bucket.ACL.Value()),
						bucket.ACL,
					)
				}
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
