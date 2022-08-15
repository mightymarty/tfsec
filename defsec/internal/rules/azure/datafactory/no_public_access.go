package datafactory

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0035",
		Provider:   providers2.AzureProvider,
		Service:    "datafactory",
		ShortCode:  "no-public-access",
		Summary:    "Data Factory should have public access disabled, the default is enabled.",
		Impact:     "Data factory is publicly accessible",
		Resolution: "Set public access to disabled for Data Factory",
		Explanation: `Data Factory has public access set to true by default.

Disabling public network access is applicable only to the self-hosted integration runtime, not to Azure Integration Runtime and SQL Server Integration Services (SSIS) Integration Runtime.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/data-factory/data-movement-security-considerations#hybrid-scenarios",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, factory := range s.Azure.DataFactory.DataFactories {
			if factory.EnablePublicNetwork.IsTrue() {
				results.Add(
					"Data factory allows public network access.",
					factory.EnablePublicNetwork,
				)
			} else {
				results.AddPassed(&factory)
			}
		}
		return
	},
)
