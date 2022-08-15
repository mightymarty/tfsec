package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicEgressSgr = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0104",
		Aliases:     []string{"aws-vpc-no-public-egress-sgr"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-public-egress-sgr",
		Summary:     "An egress security group rule allows traffic to /0.",
		Impact:      "Your port is egressing data to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressSgrGoodExamples,
			BadExamples:         terraformNoPublicEgressSgrBadExamples,
			Links:               terraformNoPublicEgressSgrLinks,
			RemediationMarkdown: terraformNoPublicEgressSgrRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicEgressSgrGoodExamples,
			BadExamples:         cloudFormationNoPublicEgressSgrBadExamples,
			Links:               cloudFormationNoPublicEgressSgrLinks,
			RemediationMarkdown: cloudFormationNoPublicEgressSgrRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range group.EgressRules {
				var fail bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						fail = true
						results.Add(
							"Security group rule allows egress to multiple public internet addresses.",
							block,
						)
					}
				}
				if !fail {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
