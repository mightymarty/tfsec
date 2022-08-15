package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0039",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "SSL policies should enforce secure versions of TLS",
		Impact:      "Data in transit is not sufficiently secured",
		Resolution:  "Enforce a minimum TLS version of 1.2",
		Explanation: `TLS versions prior to 1.2 are outdated and insecure. You should use 1.2 as aminimum version.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, policy := range s.Google.Compute.SSLPolicies {
			if policy.IsUnmanaged() {
				continue
			}
			if policy.MinimumTLSVersion.NotEqualTo("TLS_1_2") {
				results.Add(
					"TLS policy does not specify a minimum of TLS 1.2",
					policy.MinimumTLSVersion,
				)
			} else {
				results.AddPassed(&policy)
			}
		}
		return
	},
)
