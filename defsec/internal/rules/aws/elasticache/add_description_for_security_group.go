package elasticache

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAddDescriptionForSecurityGroup = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0049",
		Provider:   providers2.AWSProvider,
		Service:    "elasticache",
		ShortCode:  "add-description-for-security-group",
		Summary:    "Missing description for security group/security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups and rules",
		Explanation: `Security groups and security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAddDescriptionForSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionForSecurityGroupBadExamples,
			Links:               terraformAddDescriptionForSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionForSecurityGroupRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationAddDescriptionForSecurityGroupGoodExamples,
			BadExamples:         cloudFormationAddDescriptionForSecurityGroupBadExamples,
			Links:               cloudFormationAddDescriptionForSecurityGroupLinks,
			RemediationMarkdown: cloudFormationAddDescriptionForSecurityGroupRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, sg := range s.AWS.ElastiCache.SecurityGroups {
			if sg.Description.IsEmpty() {
				results.Add(
					"Security group does not have a description.",
					sg.Description,
				)
			} else {
				results.AddPassed(&sg)
			}
		}
		return
	},
)
