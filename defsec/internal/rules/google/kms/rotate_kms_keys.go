package kms

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckRotateKmsKeys = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0065",
		Provider:    providers2.GoogleProvider,
		Service:     "kms",
		ShortCode:   "rotate-kms-keys",
		Summary:     "KMS keys should be rotated at least every 90 days",
		Impact:      "Exposure is greater if the same keys are used over a long period",
		Resolution:  "Set key rotation period to 90 days",
		Explanation: `Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformRotateKmsKeysGoodExamples,
			BadExamples:         terraformRotateKmsKeysBadExamples,
			Links:               terraformRotateKmsKeysLinks,
			RemediationMarkdown: terraformRotateKmsKeysRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, keyring := range s.Google.KMS.KeyRings {
			for _, key := range keyring.Keys {
				if key.RotationPeriodSeconds.GreaterThan(7776000) {
					results.Add(
						"Key has a rotation period of more than 90 days.",
						key.RotationPeriodSeconds,
					)
				} else {
					results.AddPassed(&key)
				}
			}
		}
		return
	},
)
