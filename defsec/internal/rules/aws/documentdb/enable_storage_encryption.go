package documentdb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableStorageEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0021",
		Provider:    providers2.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "enable-storage-encryption",
		Summary:     "DocumentDB storage must be encrypted",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable storage encryption",
		Explanation: `Encryption of the underlying storage used by DocumentDB ensures that if their is compromise of the disks, the data is still protected.`,
		Links:       []string{"https://docs.aws.amazon.com/documentdb/latest/developerguide/encryption-at-rest.html"},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableStorageEncryptionGoodExamples,
			BadExamples:         terraformEnableStorageEncryptionBadExamples,
			Links:               terraformEnableStorageEncryptionLinks,
			RemediationMarkdown: terraformEnableStorageEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableStorageEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableStorageEncryptionBadExamples,
			Links:               cloudFormationEnableStorageEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableStorageEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster storage does not have encryption enabled.",
					cluster.StorageEncrypted,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
