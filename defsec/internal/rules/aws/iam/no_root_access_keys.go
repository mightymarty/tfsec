package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var checkNoRootAccessKeys = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0141",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "no-root-access-keys",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"1.12"},
			framework2.CIS_AWS_1_4: {"1.4"},
		},
		Summary:    "The root user has complete access to all services and resources in an AWS account. AWS Access Keys provide programmatic access to a given account.",
		Impact:     "Compromise of the root account compromises the entire AWS account and all resources within it.",
		Resolution: "Use lower privileged accounts instead, so only required privileges are available.",
		Explanation: `
CIS recommends that all access keys be associated with the root user be removed. Removing access keys associated with the root user limits vectors that the account can be compromised by. Removing the root user access keys also encourages the creation and use of role-based accounts that are least privileged.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoRootAccessKeysGoodExamples,
			BadExamples:         terraformNoRootAccessKeysBadExamples,
			Links:               terraformNoRootAccessKeysLinks,
			RemediationMarkdown: terraformNoRootAccessKeysRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, user := range s.AWS.IAM.Users {
			if user.Name.EqualTo("root") {
				var hasActiveKey bool
				for _, key := range user.AccessKeys {
					if key.Active.IsTrue() {
						results.Add("Access key exists for root user", &key)
						hasActiveKey = true
					}
				}
				if !hasActiveKey {
					results.AddPassed(&user)
				}
			}
		}
		return
	},
)
