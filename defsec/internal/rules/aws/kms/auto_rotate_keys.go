package kms

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	kms2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/kms"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAutoRotateKeys = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0065",
		Provider:    providers2.AWSProvider,
		Service:     "kms",
		ShortCode:   "auto-rotate-keys",
		Summary:     "A KMS key is not configured to auto-rotate.",
		Impact:      "Long life KMS keys increase the attack surface when compromised",
		Resolution:  "Configure KMS key to auto rotate",
		Explanation: `You should configure your KMS keys to auto rotate to maintain security and defend against compromise.`,
		Links: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAutoRotateKeysGoodExamples,
			BadExamples:         terraformAutoRotateKeysBadExamples,
			Links:               terraformAutoRotateKeysLinks,
			RemediationMarkdown: terraformAutoRotateKeysRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, key := range s.AWS.KMS.Keys {
			if key.Usage.EqualTo(kms2.KeyUsageSignAndVerify) {
				continue
			}
			if key.RotationEnabled.IsFalse() {
				results.Add(
					"Key does not have rotation enabled.",
					key.RotationEnabled,
				)
			} else {
				results.AddPassed(&key)
			}
		}
		return
	},
)
