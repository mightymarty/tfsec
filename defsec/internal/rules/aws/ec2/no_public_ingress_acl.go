package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	ec22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ec2"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicIngress = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0105",
		Aliases:     []string{"aws-vpc-no-public-ingress-acl"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-public-ingress-acl",
		Summary:     "An ingress Network ACL rule allows specific ports from /0.",
		Impact:      "The ports are exposed for ingressing data to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ACLs to the public internet is potentially dangerous. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressAclGoodExamples,
			BadExamples:         terraformNoPublicIngressAclBadExamples,
			Links:               terraformNoPublicIngressAclLinks,
			RemediationMarkdown: terraformNoPublicIngressAclRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIngressAclGoodExamples,
			BadExamples:         cloudFormationNoPublicIngressAclBadExamples,
			Links:               cloudFormationNoPublicIngressAclLinks,
			RemediationMarkdown: cloudFormationNoPublicIngressAclRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, acl := range s.AWS.EC2.NetworkACLs {
			for _, rule := range acl.Rules {
				if !rule.Type.EqualTo(ec22.TypeIngress) {
					continue
				}
				if !rule.Action.EqualTo(ec22.ActionAllow) {
					continue
				}
				var fail bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						fail = true
						results.Add(
							"Network ACL rule allows ingress from public internet.",
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
