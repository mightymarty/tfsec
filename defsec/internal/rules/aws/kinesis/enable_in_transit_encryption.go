package kinesis

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	kinesis2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/kinesis"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0064",
		Provider:    providers2.AWSProvider,
		Service:     "kinesis",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Kinesis stream is unencrypted.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enable in transit encryption",
		Explanation: `Kinesis streams should be encrypted to ensure sensitive data is kept private. Additionally, non-default KMS keys should be used so granularity of access control can be ensured.`,
		Links: []string{
			"https://docs.aws.amazon.com/streams/latest/dev/server-side-encryption.html",
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
		for _, stream := range s.AWS.Kinesis.Streams {
			if stream.Encryption.Type.NotEqualTo(kinesis2.EncryptionTypeKMS) {
				results.Add(
					"Stream does not use KMS encryption.",
					stream.Encryption.Type,
				)
			} else if stream.Encryption.KMSKeyID.IsEmpty() {
				results.Add(
					"Stream does not use a custom-managed KMS key.",
					stream.Encryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&stream)
			}
		}
		return
	},
)
