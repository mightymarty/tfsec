package neptune

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0128",
		Provider:    providers2.AWSProvider,
		Service:     "neptune",
		ShortCode:   "encryption-customer-key",
		Summary:     "Neptune encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your Neptune underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformCheckEncryptionCustomerKeyBadExamples,
			Links:               terraformCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationCheckEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationCheckEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationCheckEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationCheckEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster does not encrypt data with a customer managed key.",
					cluster.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
