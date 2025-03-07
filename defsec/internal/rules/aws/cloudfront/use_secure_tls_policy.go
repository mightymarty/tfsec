package cloudfront

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	cloudfront2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudfront"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0013",
		Provider:   providers2.AWSProvider,
		Service:    "cloudfront",
		ShortCode:  "use-secure-tls-policy",
		Summary:    "CloudFront distribution uses outdated SSL/TLS protocols.",
		Impact:     "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution: "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
		
Note: that setting *minimum_protocol_version = "TLSv1.2_2021"* is only possible when *cloudfront_default_certificate* is false (eg. you are not using the cloudfront.net domain name). 
If *cloudfront_default_certificate* is true then the Cloudfront API will only allow setting *minimum_protocol_version = "TLSv1"*, and setting it to any other value will result in a perpetual diff in your *terraform plan*'s. 
The only option when using the cloudfront.net domain name is to ignore this rule.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationUseSecureTlsPolicyGoodExamples,
			BadExamples:         cloudFormationUseSecureTlsPolicyBadExamples,
			Links:               cloudFormationUseSecureTlsPolicyLinks,
			RemediationMarkdown: cloudFormationUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.ViewerCertificate.MinimumProtocolVersion.NotEqualTo(cloudfront2.ProtocolVersionTLS1_2) {
				results.Add(
					"Distribution allows unencrypted communications.",
					dist.ViewerCertificate.MinimumProtocolVersion,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
