package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckDisablePasswordAuthentication = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0039",
		Provider:    providers2.AzureProvider,
		Service:     "compute",
		ShortCode:   "disable-password-authentication",
		Summary:     "Password authentication should be disabled on Azure virtual machines",
		Impact:      "Using password authentication is less secure that ssh keys may result in compromised servers",
		Resolution:  "Use ssh authentication for virtual machines",
		Explanation: `Access to virtual machines should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformDisablePasswordAuthenticationGoodExamples,
			BadExamples:         terraformDisablePasswordAuthenticationBadExamples,
			Links:               terraformDisablePasswordAuthenticationLinks,
			RemediationMarkdown: terraformDisablePasswordAuthenticationRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, vm := range s.Azure.Compute.LinuxVirtualMachines {
			if vm.IsUnmanaged() {
				continue
			}
			if vm.OSProfileLinuxConfig.DisablePasswordAuthentication.IsFalse() {
				results.Add(
					"Linux virtual machine allows password authentication.",
					vm.OSProfileLinuxConfig.DisablePasswordAuthentication,
				)
			} else {
				results.AddPassed(&vm)
			}
		}
		return
	},
)
