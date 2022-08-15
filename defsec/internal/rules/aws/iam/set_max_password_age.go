package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSetMaxPasswordAge = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0062",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "set-max-password-age",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.11"},
		},
		Summary:    "IAM Password policy should have expiry less than or equal to 90 days.",
		Impact:     "Long life password increase the likelihood of a password eventually being compromised",
		Resolution: "Limit the password duration with an expiry in the policy",
		Explanation: `IAM account password policies should have a maximum age specified. 
		
The account password policy should be set to expire passwords after 90 days or less.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSetMaxPasswordAgeGoodExamples,
			BadExamples:         terraformSetMaxPasswordAgeBadExamples,
			Links:               terraformSetMaxPasswordAgeLinks,
			RemediationMarkdown: terraformSetMaxPasswordAgeRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.MaxAgeDays.GreaterThan(90) {
			results.Add(
				"Password policy allows a maximum password age of greater than 90 days.",
				policy.MaxAgeDays,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
