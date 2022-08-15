package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPublicACLsAreIgnored = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0091",
		Provider:   providers2.AWSProvider,
		Service:    "s3",
		ShortCode:  "ignore-public-acls",
		Summary:    "S3 Access Block should Ignore Public Acl",
		Impact:     "PUT calls with public ACLs specified can make objects public",
		Resolution: "Enable ignoring the application of public ACLs in PUT calls",
		Explanation: `
S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformIgnorePublicAclsGoodExamples,
			BadExamples:         terraformIgnorePublicAclsBadExamples,
			Links:               terraformIgnorePublicAclsLinks,
			RemediationMarkdown: terraformIgnorePublicAclsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationIgnorePublicAclsGoodExamples,
			BadExamples:         cloudFormationIgnorePublicAclsBadExamples,
			Links:               cloudFormationIgnorePublicAclsLinks,
			RemediationMarkdown: cloudFormationIgnorePublicAclsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not ignoring public acls", &bucket)
			} else if bucket.PublicAccessBlock.IgnorePublicACLs.IsFalse() {
				results.Add(
					"Public access block does not ignore public ACLs",
					bucket.PublicAccessBlock.IgnorePublicACLs,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
