package cloudfront

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	cloudfront2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudfront"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnforceHttps = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0012",
		Provider:   providers2.AWSProvider,
		Service:    "cloudfront",
		ShortCode:  "enforce-https",
		Summary:    "CloudFront distribution allows unencrypted (HTTP) communications.",
		Impact:     "CloudFront is available through an unencrypted connection",
		Resolution: "Only allow HTTPS for CloudFront distribution communication",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-s3-origin.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforceHttpsGoodExamples,
			BadExamples:         terraformEnforceHttpsBadExamples,
			Links:               terraformEnforceHttpsLinks,
			RemediationMarkdown: terraformEnforceHttpsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnforceHttpsGoodExamples,
			BadExamples:         cloudFormationEnforceHttpsBadExamples,
			Links:               cloudFormationEnforceHttpsLinks,
			RemediationMarkdown: cloudFormationEnforceHttpsRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.DefaultCacheBehaviour.ViewerProtocolPolicy.EqualTo(cloudfront2.ViewerPolicyProtocolAllowAll) {
				results.Add(
					"Distribution allows unencrypted communications.",
					dist.DefaultCacheBehaviour.ViewerProtocolPolicy,
				)
			} else {
				results.AddPassed(&dist)
			}
			for _, behaviour := range dist.OrdererCacheBehaviours {
				if behaviour.ViewerProtocolPolicy.EqualTo(cloudfront2.ViewerPolicyProtocolAllowAll) {
					results.Add(
						"Distribution allows unencrypted communications.",
						behaviour.ViewerProtocolPolicy,
					)
				} else {
					results.AddPassed(&behaviour)
				}
			}

		}
		return
	},
)
