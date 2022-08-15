package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSetMinimumPasswordLength = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0063",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "set-minimum-password-length",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.9"},
			framework2.CIS_AWS_1_4: {"1.8"},
		},
		Summary:    "IAM Password policy should have minimum password length of 14 or more characters.",
		Impact:     "Short, simple passwords are easier to compromise",
		Resolution: "Enforce longer, more complex passwords in the policy",
		Explanation: `IAM account password policies should ensure that passwords have a minimum length. 

The account password policy should be set to enforce minimum password length of at least 14 characters.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSetMinimumPasswordLengthGoodExamples,
			BadExamples:         terraformSetMinimumPasswordLengthBadExamples,
			Links:               terraformSetMinimumPasswordLengthLinks,
			RemediationMarkdown: terraformSetMinimumPasswordLengthRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.MinimumLength.LessThan(14) {
			results.Add(
				"Password policy has a minimum password length of less than 14 characters.",
				policy.MinimumLength,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
