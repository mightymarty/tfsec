package dns

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoRsaSha1 = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0012",
		Provider:    providers2.GoogleProvider,
		Service:     "dns",
		ShortCode:   "no-rsa-sha1",
		Summary:     "Zone signing should not use RSA SHA1",
		Impact:      "Less secure encryption algorithm than others available",
		Resolution:  "Use RSA SHA512",
		Explanation: `RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoRsaSha1GoodExamples,
			BadExamples:         terraformNoRsaSha1BadExamples,
			Links:               terraformNoRsaSha1Links,
			RemediationMarkdown: terraformNoRsaSha1RemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, zone := range s.Google.DNS.ManagedZones {
			if zone.IsUnmanaged() {
				continue
			}
			if zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm.EqualTo("rsasha1") {
				results.Add(
					"Zone KSK uses RSA SHA1 for signing.",
					zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm,
				)
			} else if zone.DNSSec.DefaultKeySpecs.ZoneSigningKey.Algorithm.EqualTo("rsasha1") {
				results.Add(
					"Zone ZSK uses RSA SHA1 for signing.",
					zone.DNSSec.DefaultKeySpecs.ZoneSigningKey.Algorithm,
				)
			} else {
				results.AddPassed(&zone)
			}
		}
		return
	},
)
