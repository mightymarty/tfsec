package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoExcessivePortAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0102",
		Aliases:     []string{"aws-vpc-no-excessive-port-access"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-excessive-port-access",
		Summary:     "An ingress Network ACL rule allows ALL ports.",
		Impact:      "All ports exposed for egressing data",
		Resolution:  "Set specific allowed ports",
		Explanation: `Ensure access to specific required ports is allowed, and nothing else.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoExcessivePortAccessGoodExamples,
			BadExamples:         terraformNoExcessivePortAccessBadExamples,
			Links:               terraformNoExcessivePortAccessLinks,
			RemediationMarkdown: terraformNoExcessivePortAccessRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoExcessivePortAccessGoodExamples,
			BadExamples:         cloudFormationNoExcessivePortAccessBadExamples,
			Links:               cloudFormationNoExcessivePortAccessLinks,
			RemediationMarkdown: cloudFormationNoExcessivePortAccessRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, acl := range s.AWS.EC2.NetworkACLs {
			for _, rule := range acl.Rules {
				if rule.Protocol.EqualTo("-1") || rule.Protocol.EqualTo("all") {
					results.Add(
						"Network ACL rule allows access using ALL ports.",
						rule.Protocol,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
