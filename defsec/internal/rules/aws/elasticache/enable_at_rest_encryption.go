package elasticache

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0045",
		Provider:    providers2.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Elasticache Replication Group stores unencrypted data at-rest.",
		Impact:      "At-rest data in the Replication Group could be compromised if accessed.",
		Resolution:  "Enable at-rest encryption for replication group",
		Explanation: `Data stored within an Elasticache replication node should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.ElastiCache.ReplicationGroups {
			if group.AtRestEncryptionEnabled.IsFalse() {
				results.Add(
					"Replication group does not have at-rest encryption enabled.",
					group.AtRestEncryptionEnabled,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
