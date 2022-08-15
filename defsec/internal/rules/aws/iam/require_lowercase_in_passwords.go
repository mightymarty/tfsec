package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckRequireLowercaseInPasswords = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0058",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "require-lowercase-in-passwords",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.6"},
		},
		Summary:     "IAM Password policy should have requirement for at least one lowercase character.",
		Impact:      "Short, simple passwords are easier to compromise",
		Resolution:  "Enforce longer, more complex passwords in the policy",
		Explanation: `IAM account password policies should ensure that passwords content including at least one lowercase character.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformRequireLowercaseInPasswordsGoodExamples,
			BadExamples:         terraformRequireLowercaseInPasswordsBadExamples,
			Links:               terraformRequireLowercaseInPasswordsLinks,
			RemediationMarkdown: terraformRequireLowercaseInPasswordsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.RequireLowercase.IsFalse() {
			results.Add(
				"Password policy does not require lowercase characters.",
				policy.RequireLowercase,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
