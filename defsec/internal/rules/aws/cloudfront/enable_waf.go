package cloudfront

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableWaf = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0011",
		Provider:    providers2.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-waf",
		Summary:     "CloudFront distribution does not have a WAF in front.",
		Impact:      "Complex web application attacks can more easily be performed without a WAF",
		Resolution:  "Enable WAF for the CloudFront distribution",
		Explanation: `You should configure a Web Application Firewall in front of your CloudFront distribution. This will mitigate many types of attacks on your web application.`,
		Links: []string{
			"https://docs.aws.amazon.com/waf/latest/developerguide/cloudfront-features.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableWafGoodExamples,
			BadExamples:         terraformEnableWafBadExamples,
			Links:               terraformEnableWafLinks,
			RemediationMarkdown: terraformEnableWafRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableWafGoodExamples,
			BadExamples:         cloudFormationEnableWafBadExamples,
			Links:               cloudFormationEnableWafLinks,
			RemediationMarkdown: cloudFormationEnableWafRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.WAFID.IsEmpty() {
				results.Add(
					"Distribution does not utilise a WAF.",
					dist.WAFID,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
