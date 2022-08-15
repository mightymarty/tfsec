package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPasswordReuse = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0056",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "no-password-reuse",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.10"},
			framework2.CIS_AWS_1_4: {"1.9"},
		},
		Summary:    "IAM Password policy should prevent password reuse.",
		Impact:     "Password reuse increase the risk of compromised passwords being abused",
		Resolution: "Prevent password reuse in the policy",
		Explanation: `IAM account password policies should prevent the reuse of passwords. 

The account password policy should be set to prevent using any of the last five used passwords.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPasswordReuseGoodExamples,
			BadExamples:         terraformNoPasswordReuseBadExamples,
			Links:               terraformNoPasswordReuseLinks,
			RemediationMarkdown: terraformNoPasswordReuseRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {

		policy := s.AWS.IAM.PasswordPolicy
		if policy.IsUnmanaged() {
			return
		}

		if policy.ReusePreventionCount.LessThan(5) {
			results.Add(
				"Password policy allows reuse of recent passwords.",
				policy.ReusePreventionCount,
			)
		} else {
			results.AddPassed(&policy)
		}
		return
	},
)
