package datalake

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0036",
		Provider:    providers2.AzureProvider,
		Service:     "datalake",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Unencrypted data lake storage.",
		Impact:      "Data could be read if compromised",
		Resolution:  "Enable encryption of data lake storage",
		Explanation: `Datalake storage encryption defaults to Enabled, it shouldn't be overridden to Disabled.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/data-lake-store/data-lake-store-security-overview",
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
		for _, store := range s.Azure.DataLake.Stores {
			if store.EnableEncryption.IsFalse() {
				results.Add(
					"Data lake store is not encrypted.",
					store.EnableEncryption,
				)
			} else {
				results.AddPassed(&store)
			}
		}
		return
	},
)
