package ec2

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"

	"github.com/owenrumney/squealer/pkg/squealer"
)

var CheckNoSensitiveInfo = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0122",
		Aliases:     []string{"aws-autoscaling-no-sensitive-info"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-sensitive-info",
		Summary:     "Ensure all data stored in the launch configuration EBS is securely encrypted",
		Impact:      "Sensitive credentials in user data can be leaked",
		Resolution:  "Don't use sensitive data in user data",
		Explanation: `When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoSensitiveInfoGoodExamples,
			BadExamples:         terraformNoSensitiveInfoBadExamples,
			Links:               terraformNoSensitiveInfoLinks,
			RemediationMarkdown: terraformNoSensitiveInfoRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		scanner := squealer.NewStringScanner()
		for _, launchConfig := range s.AWS.EC2.LaunchConfigurations {
			if result := scanner.Scan(launchConfig.UserData.Value()); result.TransgressionFound {
				results.Add(
					fmt.Sprintf("Sensitive data found in user data: %s", result.Description),
					launchConfig.UserData,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
		}
		return
	},
)
