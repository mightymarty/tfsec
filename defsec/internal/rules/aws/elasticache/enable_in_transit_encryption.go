package elasticache

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0051",
		Provider:    providers2.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Elasticache Replication Group uses unencrypted traffic.",
		Impact:      "In transit data in the Replication Group could be read if intercepted",
		Resolution:  "Enable in transit encryption for replication group",
		Explanation: `Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.ElastiCache.ReplicationGroups {
			if group.TransitEncryptionEnabled.IsFalse() {
				results.Add(
					"Replication group does not have transit encryption enabled.",
					group.TransitEncryptionEnabled,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
