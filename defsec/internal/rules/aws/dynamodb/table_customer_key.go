package dynamodb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	dynamodb2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/dynamodb"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckTableCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0025",
		Provider:    providers2.AWSProvider,
		Service:     "dynamodb",
		ShortCode:   "table-customer-key",
		Summary:     "DynamoDB tables should use at rest encryption with a Customer Managed Key",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable server side encryption with a customer managed key",
		Explanation: `DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformTableCustomerKeyGoodExamples,
			BadExamples:         terraformTableCustomerKeyBadExamples,
			Links:               terraformTableCustomerKeyLinks,
			RemediationMarkdown: terraformTableCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.DynamoDB.DAXClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.ServerSideEncryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster encryption does not use a customer-managed KMS key.",
					cluster.ServerSideEncryption.KMSKeyID,
				)
			} else if cluster.ServerSideEncryption.KMSKeyID.EqualTo(dynamodb2.DefaultKMSKeyID) {
				results.Add(
					"Cluster encryption explicitly uses the default KMS key.",
					cluster.ServerSideEncryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		for _, table := range s.AWS.DynamoDB.Tables {
			if table.IsUnmanaged() {
				continue
			}
			if table.ServerSideEncryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Table encryption does not use a customer-managed KMS key.",
					table.ServerSideEncryption.KMSKeyID,
				)
			} else if table.ServerSideEncryption.KMSKeyID.EqualTo(dynamodb2.DefaultKMSKeyID) {
				results.Add(
					"Table encryption explicitly uses the default KMS key.",
					table.ServerSideEncryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&table)
			}
		}
		return
	},
)
