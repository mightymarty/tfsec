package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableShieldedVMIntegrityMonitoring = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0045",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-im",
		Summary:     "Instances should have Shielded VM integrity monitoring enabled",
		Impact:      "No visibility of VM instance boot state.",
		Resolution:  "Enable Shielded VM Integrity Monitoring",
		Explanation: `Integrity monitoring helps you understand and make decisions about the state of your VM instances.`,
		Links: []string{
			"https://cloud.google.com/security/shielded-cloud/shielded-vm#integrity-monitoring",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableShieldedVmImGoodExamples,
			BadExamples:         terraformEnableShieldedVmImBadExamples,
			Links:               terraformEnableShieldedVmImLinks,
			RemediationMarkdown: terraformEnableShieldedVmImRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.ShieldedVM.IntegrityMonitoringEnabled.IsFalse() {
				results.Add(
					"Instance does not have shielded VM integrity monitoring enabled.",
					instance.ShieldedVM.IntegrityMonitoringEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
