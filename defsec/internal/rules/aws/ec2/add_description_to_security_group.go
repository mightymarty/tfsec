package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAddDescriptionToSecurityGroup = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0099",
		Aliases:    []string{"aws-vpc-add-description-to-security-group"},
		Provider:   providers2.AWSProvider,
		Service:    "ec2",
		ShortCode:  "add-description-to-security-group",
		Summary:    "Missing description for security group.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups",
		Explanation: `Security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationAddDescriptionToSecurityGroupGoodExamples,
			BadExamples:         cloudFormationAddDescriptionToSecurityGroupBadExamples,
			Links:               cloudFormationAddDescriptionToSecurityGroupLinks,
			RemediationMarkdown: cloudFormationAddDescriptionToSecurityGroupRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			if group.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"Security group does not have a description.",
					group.Description,
				)
			} else if group.Description.EqualTo("Managed by Terraform") {
				results.Add(
					"Security group explicitly uses the default description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
