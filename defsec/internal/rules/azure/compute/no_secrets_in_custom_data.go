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

var CheckNoSecretsInCustomData = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0037",
		Provider:    providers2.AzureProvider,
		Service:     "compute",
		ShortCode:   "no-secrets-in-custom-data",
		Summary:     "Ensure that no sensitive credentials are exposed in VM custom_data",
		Impact:      "Sensitive credentials in custom_data can be leaked",
		Resolution:  "Don't use sensitive credentials in the VM custom_data",
		Explanation: `When creating Azure Virtual Machines, custom_data is used to pass start up information into the EC2 instance. This custom_dat must not contain access key credentials.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoSecretsInCustomDataGoodExamples,
			BadExamples:         terraformNoSecretsInCustomDataBadExamples,
			Links:               terraformNoSecretsInCustomDataLinks,
			RemediationMarkdown: terraformNoSecretsInCustomDataRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, vm := range s.Azure.Compute.LinuxVirtualMachines {
			if vm.IsUnmanaged() {
				continue
			}
			if result := scanner.Scan(vm.CustomData.Value()); result.TransgressionFound {
				results.Add(
					"Virtual machine includes secret(s) in custom data.",
					vm.CustomData,
				)
			} else {
				results.AddPassed(&vm)
			}
		}
		for _, vm := range s.Azure.Compute.WindowsVirtualMachines {
			if vm.IsUnmanaged() {
				continue
			}
			if result := scanner.Scan(vm.CustomData.Value()); result.TransgressionFound {
				results.Add(
					"Virtual machine includes secret(s) in custom data.",
					vm.CustomData,
				)
			} else {
				results.AddPassed(&vm)
			}
		}
		return
	},
)
