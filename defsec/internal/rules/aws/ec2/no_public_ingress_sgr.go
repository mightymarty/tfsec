package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicIngressSgr = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0107",
		Aliases:   []string{"aws-vpc-no-public-ingress-sgr"},
		Provider:  providers2.AWSProvider,
		Service:   "ec2",
		ShortCode: "no-public-ingress-sgr",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"4.1", "4.2"},
		},
		Summary:     "An ingress security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressSgrBadExamples,
			Links:               terraformNoPublicIngressSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressSgrRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressSgrGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressSgrBadExamples,
			Links:               cloudFormationNoPublicIngressSgrLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressSgrRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range group.IngressRules {
				var failed bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						failed = true
						results.Add(
							"Security group rule allows ingress from public internet.",
							block,
						)
					}
				}
				if !failed {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
