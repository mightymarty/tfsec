package rds

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptClusterStorageData = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0079",
		Provider:   providers2.AWSProvider,
		Service:    "rds",
		ShortCode:  "encrypt-cluster-storage-data",
		Summary:    "There is no encryption specified or encryption is disabled on the RDS Cluster.",
		Impact:     "Data can be read from the RDS cluster if it is compromised",
		Resolution: "Enable encryption for RDS clusters",
		Explanation: `Encryption should be enabled for an RDS Aurora cluster. 

When enabling encryption by setting the kms_key_id, the storage_encrypted must also be set to true.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEncryptClusterStorageDataGoodExamples,
			BadExamples:         terraformEncryptClusterStorageDataBadExamples,
			Links:               terraformEncryptClusterStorageDataLinks,
			RemediationMarkdown: terraformEncryptClusterStorageDataRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEncryptClusterStorageDataGoodExamples,
			BadExamples:         cloudFormationEncryptClusterStorageDataBadExamples,
			Links:               cloudFormationEncryptClusterStorageDataLinks,
			RemediationMarkdown: cloudFormationEncryptClusterStorageDataRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.Encryption.EncryptStorage.IsFalse() {
				results.Add(
					"Cluster does not have storage encryption enabled.",
					cluster.Encryption.EncryptStorage,
				)
			} else if cluster.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster does not specify a customer managed key for storage encryption.",
					cluster.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
