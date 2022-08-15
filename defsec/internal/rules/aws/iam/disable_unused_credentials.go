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

var CheckUnusedCredentialsDisabled = rules.Register(
	scan2.Rule{
		AVDID:    "AVD-AWS-0144",
		Provider: providers2.AWSProvider,
		Frameworks: map[framework2.Framework][]string{
			framework2.CIS_AWS_1_2: {"1.3"},
		},
		Service:    "iam",
		ShortCode:  "disable-unused-credentials",
		Summary:    "Credentials which are no longer used should be disabled.",
		Impact:     "Leaving unused credentials active widens the scope for compromise.",
		Resolution: "Disable credentials which are no longer used.",
		Explanation: `
CIS recommends that you remove or deactivate all credentials that have been unused in 90 days or more. Disabling or removing unnecessary credentials reduces the window of opportunity for credentials associated with a compromised or abandoned account to be used.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {

		for _, user := range s.AWS.IAM.Users {
			if user.HasLoggedIn() && user.LastAccess.Before(time.Now().Add(-90*24*time.Hour)) {
				results.Add("User has not logged in for >90 days", &user)
				continue
			}
			var hasKey bool
			for _, key := range user.AccessKeys {
				if key.Active.IsFalse() || !key.LastAccess.GetMetadata().IsResolvable() ||
					key.LastAccess.After(time.Now().Add(-90*24*time.Hour)) {
					continue
				}
				results.Add(fmt.Sprintf("User access key '%s' has not been used in >90 days", key.AccessKeyId.Value()), &user)
				hasKey = true
			}
			if !hasKey {
				results.AddPassed(&user)
			}
		}

		return
	},
)
