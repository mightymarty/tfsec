package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"time"
)

var checkLimitRootAccountUsage = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0140",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "limit-root-account-usage",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.1"},
			framework2.CIS_AWS_1_4: {"1.7"},
		},
		Summary:    "The \"root\" account has unrestricted access to all resources in the AWS account. It is highly\nrecommended that the use of this account be avoided.",
		Impact:     "Compromise of the root account compromises the entire AWS account and all resources within it.",
		Resolution: "Use lower privileged accounts instead, so only required privileges are available.",
		Explanation: `
The root user has unrestricted access to all services and resources in an AWS account. We highly recommend that you avoid using the root user for daily tasks. Minimizing the use of the root user and adopting the principle of least privilege for access management reduce the risk of accidental changes and unintended disclosure of highly privileged credentials.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, user := range s.AWS.IAM.Users {
			if user.Name.EqualTo("root") {
				if user.LastAccess.After(time.Now().Add(-time.Hour * 24)) {
					results.Add("The root user logged in within the last 24 hours", user.LastAccess)
				} else {
					results.AddPassed(&user)
				}
				break
			}
		}
		return
	},
)
