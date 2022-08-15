package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var checkNoUserAttachedPolicies = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0143",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "no-user-attached-policies",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.16"},
			framework2.CIS_AWS_1_4: {"1.15"},
		},
		Summary:    "IAM policies should not be granted directly to users.",
		Impact:     "Complex access control is difficult to manage and maintain.",
		Resolution: "Grant policies at the group level instead.",
		Explanation: `
CIS recommends that you apply IAM policies directly to groups and roles but not users. Assigning privileges at the group or role level reduces the complexity of access management as the number of users grow. Reducing access management complexity might in turn reduce opportunity for a principal to inadvertently receive or retain excessive privileges.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoUserAttachedPoliciesGoodExamples,
			BadExamples:         terraformNoUserAttachedPoliciesBadExamples,
			Links:               terraformNoUserAttachedPoliciesLinks,
			RemediationMarkdown: terraformNoUserAttachedPoliciesRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, user := range s.AWS.IAM.Users {
			if len(user.Policies) > 0 {
				results.Add("One or more policies are attached directly to a user", &user)
			} else {
				results.AddPassed(&user)
			}
		}
		return
	},
)
