package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableShieldedVMVTPM = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0041",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-vtpm",
		Summary:     "Instances should have Shielded VM VTPM enabled",
		Impact:      "Unable to prevent unwanted system state modification",
		Resolution:  "Enable Shielded VM VTPM",
		Explanation: `The virtual TPM provides numerous security measures to your VM.`,
		Links: []string{
			"https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableShieldedVmVtpmGoodExamples,
			BadExamples:         terraformEnableShieldedVmVtpmBadExamples,
			Links:               terraformEnableShieldedVmVtpmLinks,
			RemediationMarkdown: terraformEnableShieldedVmVtpmRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.ShieldedVM.VTPMEnabled.IsFalse() {
				results.Add(
					"Instance does not have VTPM for shielded VMs enabled.",
					instance.ShieldedVM.VTPMEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
