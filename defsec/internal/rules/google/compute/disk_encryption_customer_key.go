package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckDiskEncryptionCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0034",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "disk-encryption-customer-key",
		Summary:     "Disks should be encrypted with customer managed encryption keys",
		Impact:      "Using unmanaged keys does not allow for proper key management.",
		Resolution:  "Use managed keys to encrypt disks.",
		Explanation: `Using unmanaged keys makes rotation and general management difficult.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformDiskEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformDiskEncryptionCustomerKeyBadExamples,
			Links:               terraformDiskEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformDiskEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, disk := range s.Google.Compute.Disks {
			if disk.IsUnmanaged() {
				continue
			}
			if disk.Encryption.KMSKeyLink.IsEmpty() {
				results.Add(
					"Disk is not encrypted with a customer managed key.",
					disk.Encryption.KMSKeyLink,
				)
			} else {
				results.AddPassed(&disk)
			}
		}
		return
	},
)
