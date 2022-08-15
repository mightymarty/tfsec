package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var checkRootMFAEnabled = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0142",
		Provider:  providers2.AWSProvider,
		Service:   "iam",
		ShortCode: "enforce-root-mfa",
		Frameworks: map[framework2.Framework][]string{
			framework2.CIS_AWS_1_2: {"1.13"},
			framework2.CIS_AWS_1_4: {"1.5"},
		},
		Summary:    "The \"root\" account has unrestricted access to all resources in the AWS account. It is highly\nrecommended that this account have MFA enabled.",
		Impact:     "Compromise of the root account compromises the entire AWS account and all resources within it.",
		Resolution: "Enable MFA on the root user account.",
		Explanation: `
MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and password and for an authentication code from their AWS MFA device.

When you use virtual MFA for the root user, CIS recommends that the device used is not a personal device. Instead, use a dedicated mobile device (tablet or phone) that you manage to keep charged and secured independent of any individual personal devices. This lessens the risks of losing access to the MFA due to device loss, device trade-in, or if the individual owning the device is no longer employed at the company.
			`,
		Links: []string{
			"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.14",
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, user := range s.AWS.IAM.Users {
			if user.Name.EqualTo("root") {
				if len(user.MFADevices) == 0 {
					results.Add("Root user does not have an MFA device", &user)
				} else {
					results.AddPassed(&user)
				}
			}
		}
		return
	},
)
