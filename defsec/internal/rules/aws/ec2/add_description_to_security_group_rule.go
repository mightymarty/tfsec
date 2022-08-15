package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAddDescriptionToSecurityGroupRule = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0124",
		Aliases:    []string{"aws-vpc-add-description-to-security-group-rule"},
		Provider:   providers2.AWSProvider,
		Service:    "ec2",
		ShortCode:  "add-description-to-security-group-rule",
		Summary:    "Missing description for security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups rules",
		Explanation: `Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupRuleGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupRuleBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupRuleLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRuleRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationAddDescriptionToSecurityGroupRuleGoodExamples,
			BadExamples:         cloudFormationAddDescriptionToSecurityGroupRuleBadExamples,
			Links:               cloudFormationAddDescriptionToSecurityGroupRuleLinks,
			RemediationMarkdown: cloudFormationAddDescriptionToSecurityGroupRuleRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range append(group.EgressRules, group.IngressRules...) {
				if rule.Description.IsEmpty() {
					results.Add(
						"Security group rule does not have a description.",
						rule.Description,
					)
				} else {
					results.AddPassed(&rule)
				}
			}

		}
		return
	},
)
