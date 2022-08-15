package keyvault

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnsureSecretExpiry = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0017",
		Provider:   providers2.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "ensure-secret-expiry",
		Summary:    "Key Vault Secret should have an expiration date set",
		Impact:     "Long life secrets increase the opportunity for compromise",
		Resolution: "Set an expiry for secrets",
		Explanation: `Expiration Date is an optional Key Vault Secret behavior and is not set by default.

Set when the resource will be become inactive.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnsureSecretExpiryGoodExamples,
			BadExamples:         terraformEnsureSecretExpiryBadExamples,
			Links:               terraformEnsureSecretExpiryLinks,
			RemediationMarkdown: terraformEnsureSecretExpiryRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			for _, secret := range vault.Secrets {
				if secret.ExpiryDate.IsNever() {
					results.Add(
						"Secret should have an expiry date specified.",
						secret.ExpiryDate,
					)
				} else {
					results.AddPassed(&secret)
				}
			}
		}
		return
	},
)
