package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPublicPoliciesAreBlocked = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0087",
		Provider:   providers2.AWSProvider,
		Service:    "s3",
		ShortCode:  "block-public-policy",
		Summary:    "S3 Access block should block public policy",
		Impact:     "Users could put a policy that allows public access",
		Resolution: "Prevent policies that allow public access being PUT",
		Explanation: `
S3 bucket policy should have block public policy to prevent users from putting a policy that enable public access.
`,

		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/dev-retired/access-control-block-public-access.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformBlockPublicPolicyGoodExamples,
			BadExamples:         terraformBlockPublicPolicyBadExamples,
			Links:               terraformBlockPublicPolicyLinks,
			RemediationMarkdown: terraformBlockPublicPolicyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationBlockPublicPolicyGoodExamples,
			BadExamples:         cloudFormationBlockPublicPolicyBadExamples,
			Links:               cloudFormationBlockPublicPolicyLinks,
			RemediationMarkdown: cloudFormationBlockPublicPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not blocking public policies", &bucket)
			} else if bucket.PublicAccessBlock.BlockPublicPolicy.IsFalse() {
				results.Add(
					"Public access block does not block public policies",
					bucket.PublicAccessBlock.BlockPublicPolicy,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
