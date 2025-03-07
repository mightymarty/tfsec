package storage

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAllowMicrosoftServiceBypass = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0010",
		Provider:   providers2.AzureProvider,
		Service:    "storage",
		ShortCode:  "allow-microsoft-service-bypass",
		Summary:    "Trusted Microsoft Services should have bypass access to Storage accounts",
		Impact:     "Trusted Microsoft Services won't be able to access storage account unless rules set to allow",
		Resolution: "Allow Trusted Microsoft Services to bypass",
		Explanation: `Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules. 

To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAllowMicrosoftServiceBypassGoodExamples,
			BadExamples:         terraformAllowMicrosoftServiceBypassBadExamples,
			Links:               terraformAllowMicrosoftServiceBypassLinks,
			RemediationMarkdown: terraformAllowMicrosoftServiceBypassRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			for _, rule := range account.NetworkRules {
				var found bool
				for _, bypass := range rule.Bypass {
					if bypass.EqualTo("AzureServices") {
						found = true
					}
				}
				if !found {
					results.Add(
						"Network rules do not allow bypass for Microsoft Services.",
						&rule,
					)
				} else {
					results.AddPassed(&rule)
				}

			}
		}
		return
	},
)
