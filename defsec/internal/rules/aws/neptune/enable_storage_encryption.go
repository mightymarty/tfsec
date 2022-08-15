package neptune

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableStorageEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0076",
		Provider:    providers2.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-storage-encryption",
		Summary:     "Neptune storage must be encrypted at rest",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of Neptune storage",
		Explanation: `Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html",
		},
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
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster does not have storage encryption enabled.",
					cluster.StorageEncrypted,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
