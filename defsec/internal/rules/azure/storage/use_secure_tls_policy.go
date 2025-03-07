package storage

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0011",
		Provider:   providers2.AzureProvider,
		Service:    "storage",
		ShortCode:  "use-secure-tls-policy",
		Summary:    "The minimum TLS version for Storage Accounts should be TLS1_2",
		Impact:     "The TLS version being outdated and has known vulnerabilities",
		Resolution: "Use a more recent TLS/SSL policy for the load balancer",
		Explanation: `Azure Storage currently supports three versions of the TLS protocol: 1.0, 1.1, and 1.2. 

Azure Storage uses TLS 1.2 on public HTTPS endpoints, but TLS 1.0 and TLS 1.1 are still supported for backward compatibility.

This check will warn if the minimum TLS is not set to TLS1_2.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			if account.IsUnmanaged() {
				continue
			}
			if account.MinimumTLSVersion.NotEqualTo("TLS1_2") {
				results.Add(
					"Storage account uses an insecure TLS version.",
					account.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&account)
			}
		}
		return
	},
)
