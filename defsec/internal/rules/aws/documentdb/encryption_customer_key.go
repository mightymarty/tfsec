package documentdb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0022",
		Provider:    providers2.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "encryption-customer-key",
		Summary:     "DocumentDB encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links:       []string{"https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.public-key.html"},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformEncryptionCustomerKeyBadExamples,
			Links:               terraformEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.IsManaged() && cluster.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster encryption does not use a customer-managed KMS key.",
					cluster.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
			for _, instance := range cluster.Instances {
				if instance.IsUnmanaged() {
					continue
				}
				if instance.KMSKeyID.IsEmpty() {
					results.Add(
						"Instance encryption does not use a customer-managed KMS key.",
						instance.KMSKeyID,
					)
				} else {
					results.AddPassed(&cluster)
				}

			}
		}
		return
	},
)
