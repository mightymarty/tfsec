package athena

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	athena2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/athena"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0006",
		Provider:    providers2.AWSProvider,
		Service:     "athena",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted",
		Impact:      "Data can be read if the Athena Database is compromised",
		Resolution:  "Enable encryption at rest for Athena databases and workgroup configurations",
		Explanation: `Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/encryption.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableAtRestEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableAtRestEncryptionBadExamples,
			Links:               cloudFormationEnableAtRestEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if workgroup.IsUnmanaged() {
				continue
			}
			if workgroup.Encryption.Type.EqualTo(athena2.EncryptionTypeNone) {
				results.Add(
					"Workgroup does not have encryption configured.",
					workgroup.Encryption.Type,
				)
			} else {
				results.AddPassed(&workgroup)
			}
		}
		for _, database := range s.AWS.Athena.Databases {
			if database.IsUnmanaged() {
				continue
			}
			if database.Encryption.Type.EqualTo(athena2.EncryptionTypeNone) {
				results.Add(
					"Database does not have encryption configured.",
					database.Encryption.Type,
				)
			} else {
				results.AddPassed(&database)
			}
		}
		return
	},
)
