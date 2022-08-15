package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckVmDiskEncryptionCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0033",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "vm-disk-encryption-customer-key",
		Summary:     "VM disks should be encrypted with Customer Supplied Encryption Keys",
		Impact:      "Using unmanaged keys does not allow for proper management",
		Resolution:  "Use managed keys ",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformVmDiskEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformVmDiskEncryptionCustomerKeyBadExamples,
			Links:               terraformVmDiskEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformVmDiskEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			for _, disk := range append(instance.BootDisks, instance.AttachedDisks...) {
				if disk.Encryption.KMSKeyLink.IsEmpty() {
					results.Add(
						"Instance disk encryption does not use a customer managed key.",
						disk.Encryption.KMSKeyLink,
					)
				} else {
					results.AddPassed(&disk)
				}
			}
		}
		return
	},
)
