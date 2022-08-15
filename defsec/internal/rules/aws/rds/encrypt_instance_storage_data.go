package rds

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptInstanceStorageData = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0080",
		Provider:   providers2.AWSProvider,
		Service:    "rds",
		ShortCode:  "encrypt-instance-storage-data",
		Summary:    "RDS encryption has not been enabled at a DB Instance level.",
		Impact:     "Data can be read from RDS instances if compromised",
		Resolution: "Enable encryption for RDS instances",
		Explanation: `Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEncryptInstanceStorageDataGoodExamples,
			BadExamples:         terraformEncryptInstanceStorageDataBadExamples,
			Links:               terraformEncryptInstanceStorageDataLinks,
			RemediationMarkdown: terraformEncryptInstanceStorageDataRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEncryptInstanceStorageDataGoodExamples,
			BadExamples:         cloudFormationEncryptInstanceStorageDataBadExamples,
			Links:               cloudFormationEncryptInstanceStorageDataLinks,
			RemediationMarkdown: cloudFormationEncryptInstanceStorageDataRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.AWS.RDS.Instances {
			if !instance.ReplicationSourceARN.IsEmpty() {
				continue
			}
			if instance.Encryption.EncryptStorage.IsFalse() {
				results.Add(
					"Instance does not have storage encryption enabled.",
					instance.Encryption.EncryptStorage,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
