package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPublicACLsAreBlocked = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0086",
		Provider:   providers2.AWSProvider,
		Service:    "s3",
		ShortCode:  "block-public-acls",
		Summary:    "S3 Access block should block public ACL",
		Impact:     "PUT calls with public ACLs specified can make objects public",
		Resolution: "Enable blocking any PUT calls with a public ACL specified",
		Explanation: `
S3 buckets should block public ACLs on buckets and any objects they contain. By blocking, PUTs with fail if the object has any public ACL a.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformBlockPublicAclsGoodExamples,
			BadExamples:         terraformBlockPublicAclsBadExamples,
			Links:               terraformBlockPublicAclsLinks,
			RemediationMarkdown: terraformBlockPublicAclsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationBlockPublicAclsGoodExamples,
			BadExamples:         cloudFormationBlockPublicAclsBadExamples,
			Links:               cloudFormationBlockPublicAclsLinks,
			RemediationMarkdown: cloudFormationBlockPublicAclsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not blocking public acls", &bucket)
			} else if bucket.PublicAccessBlock.BlockPublicACLs.IsFalse() {
				results.Add(
					"Public access block does not block public ACLs",
					bucket.PublicAccessBlock.BlockPublicACLs,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
