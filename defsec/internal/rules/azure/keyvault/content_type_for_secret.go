package keyvault

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckContentTypeForSecret = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0015",
		Provider:   providers2.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "content-type-for-secret",
		Summary:    "Key vault Secret should have a content type set",
		Impact:     "The secret's type is unclear without a content type",
		Resolution: "Provide content type for secrets to aid interpretation on retrieval",
		Explanation: `Content Type is an optional Key Vault Secret behavior and is not enabled by default.

Clients may specify the content type of a secret to assist in interpreting the secret data when it's retrieved. The maximum length of this field is 255 characters. There are no pre-defined values. The suggested usage is as a hint for interpreting the secret data.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformContentTypeForSecretGoodExamples,
			BadExamples:         terraformContentTypeForSecretBadExamples,
			Links:               terraformContentTypeForSecretLinks,
			RemediationMarkdown: terraformContentTypeForSecretRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			for _, secret := range vault.Secrets {
				if secret.ContentType.IsEmpty() {
					results.Add(
						"Secret does not have a content-type specified.",
						secret.ContentType,
					)
				} else {
					results.AddPassed(&secret)
				}
			}
		}
		return
	},
)
