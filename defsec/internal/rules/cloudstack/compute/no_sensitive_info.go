package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"github.com/owenrumney/squealer/pkg/squealer"
)

var scanner = squealer.NewStringScanner()

var CheckNoSensitiveInfo = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-CLDSTK-0001",
		Provider:    providers2.CloudStackProvider,
		Service:     "compute",
		ShortCode:   "no-sensitive-info",
		Summary:     "No sensitive data stored in user_data",
		Impact:      "Sensitive credentials in the user data can be leaked",
		Resolution:  "Don't use sensitive data in the user data section",
		Explanation: `When creating instances, user data can be used during the initial configuration. User data must not contain sensitive information`,
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
		for _, instance := range s.CloudStack.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if scanner.Scan(instance.UserData.Value()).TransgressionFound {
				results.Add(
					"Instance user data contains secret(s).",
					instance.UserData,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
