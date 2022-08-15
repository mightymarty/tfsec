package redshift

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAddDescriptionToSecurityGroup = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0083",
		Provider:   providers2.AWSProvider,
		Service:    "redshift",
		ShortCode:  "add-description-to-security-group",
		Summary:    "Missing description for security group/security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups and rules",
		Explanation: `Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html",
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
		for _, group := range s.AWS.Redshift.SecurityGroups {
			if group.Description.IsEmpty() {
				results.Add(
					"Security group has no description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
