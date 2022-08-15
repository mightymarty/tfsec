package iam

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"time"
)

var CheckAccessKeysRotated = rules.Register(
	scan2.Rule{
		AVDID:    "AVD-AWS-0146",
		Provider: providers2.AWSProvider,
		Frameworks: map[framework2.Framework][]string{
			framework2.CIS_AWS_1_2: {"1.4"},
			framework2.CIS_AWS_1_4: {"1.14"},
		},
		Service:    "iam",
		ShortCode:  "rotate-access-keys",
		Summary:    "Access keys should be rotated at least every 90 days",
		Impact:     "Compromised keys are more likely to be used to compromise the account",
		Resolution: "Rotate keys every 90 days or less",
		Explanation: `
Regularly rotating your IAM credentials helps prevent a compromised set of IAM access keys from accessing components in your AWS account.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automatically-rotate-iam-user-access-keys-at-scale-with-aws-organizations-and-aws-secrets-manager.html",
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {

		for _, user := range s.AWS.IAM.Users {
			var hasKey bool
			for _, key := range user.AccessKeys {
				if key.Active.IsFalse() {
					continue
				}
				if key.CreationDate.Before(time.Now().Add(-time.Hour * 24 * 90)) {
					days := int(time.Since(key.CreationDate.Value().Add(-time.Hour*24*90)).Hours() / 24)
					if days == 0 {
						days = 1
					}
					results.Add(fmt.Sprintf("User access key '%s' should have been rotated %d day(s) ago", key.AccessKeyId.Value(), days), &user)
					hasKey = true
				}
			}
			if !hasKey {
				results.AddPassed(&user)
			}
		}

		return
	},
)
