package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnforceUserMFA = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0145",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "enforce-user-mfa",
		Frameworks: map[framework2.Framework][]string{
			framework2.CIS_AWS_1_2: {"1.2"},
			framework2.CIS_AWS_1_4: {"1.4"},
		},
		Summary:    "IAM Users should have MFA enforcement activated.",
		Impact:     "User accounts are more vulnerable to compromise without multi factor authentication activated",
		Resolution: "Enable MFA for the user account",
		Explanation: `
IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {

		for _, user := range s.AWS.IAM.Users {
			if user.HasLoggedIn() && len(user.MFADevices) == 0 {
				results.Add("User account does not have MFA", &user)
			} else {
				results.AddPassed(&user)
			}
		}

		return
	},
)
