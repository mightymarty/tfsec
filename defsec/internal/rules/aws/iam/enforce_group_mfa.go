package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"strings"
)

var CheckEnforceGroupMFA = rules.Register(
	scan2.Rule{
		AVDID: "AVD-AWS-0123",
		Aliases: []string{
			"aws-iam-enforce-mfa",
		},
		Provider:   providers2.AWSProvider,
		Service:    "iam",
		ShortCode:  "enforce-group-mfa",
		Summary:    "IAM groups should have MFA enforcement activated.",
		Impact:     "IAM groups are more vulnerable to compromise without multi factor authentication activated",
		Resolution: "Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced",
		Explanation: `
IAM groups should be protected with multi factor authentication to add safe guards to password compromise.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforceMfaGoodExamples,
			BadExamples:         terraformEnforceMfaBadExamples,
			Links:               terraformEnforceMfaLinks,
			RemediationMarkdown: terraformEnforceMfaRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {

		for _, group := range s.AWS.IAM.Groups {
			var mfaEnforced bool
			for _, policy := range group.Policies {
				document := policy.Document.Parsed
				statements, _ := document.Statements()
				for _, statement := range statements {
					conditions, _ := statement.Conditions()
					for _, condition := range conditions {
						key, _ := condition.Key()
						if strings.EqualFold(key, "aws:MultiFactorAuthPresent") {
							mfaEnforced = true
							break
						}
					}
				}
			}
			if !mfaEnforced {
				results.Add("Multi-Factor authentication is not enforced for group", &group)
			}
		}

		return
	},
)
