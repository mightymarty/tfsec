package msk

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	msk2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/msk"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0073",
		Provider:    providers2.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "A MSK cluster allows unencrypted data in transit.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enable in transit encryption",
		Explanation: `Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
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
		for _, cluster := range s.AWS.MSK.Clusters {
			if cluster.EncryptionInTransit.ClientBroker.EqualTo(msk2.ClientBrokerEncryptionPlaintext) {
				results.Add(
					"Cluster allows plaintext communication.",
					cluster.EncryptionInTransit.ClientBroker,
				)
			} else if cluster.EncryptionInTransit.ClientBroker.EqualTo(msk2.ClientBrokerEncryptionTLSOrPlaintext) {
				results.Add(
					"Cluster allows plaintext communication.",
					cluster.EncryptionInTransit.ClientBroker,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
