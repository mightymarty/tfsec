package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableDiskEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0038",
		Provider:    providers2.AzureProvider,
		Service:     "compute",
		ShortCode:   "enable-disk-encryption",
		Summary:     "Enable disk encryption on managed disk",
		Impact:      "Data could be read if compromised",
		Resolution:  "Enable encryption on managed disks",
		Explanation: `Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableDiskEncryptionGoodExamples,
			BadExamples:         terraformEnableDiskEncryptionBadExamples,
			Links:               terraformEnableDiskEncryptionLinks,
			RemediationMarkdown: terraformEnableDiskEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, disk := range s.Azure.Compute.ManagedDisks {
			if disk.IsUnmanaged() {
				continue
			}
			if disk.Encryption.Enabled.IsFalse() {
				results.Add(
					"Managed disk is not encrypted.",
					disk.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&disk)
			}
		}
		return
	},
)
