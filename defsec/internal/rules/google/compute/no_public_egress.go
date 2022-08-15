package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicEgress = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-GCP-0035",
		Provider:   providers2.GoogleProvider,
		Service:    "compute",
		ShortCode:  "no-public-egress",
		Summary:    "An outbound firewall rule allows traffic to /0.",
		Impact:     "The port is exposed for egress to the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.`,
		Links: []string{
			"https://cloud.google.com/vpc/docs/using-firewalls",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			Links:               terraformNoPublicEgressLinks,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, network := range s.Google.Compute.Networks {
			if network.Firewall == nil {
				continue
			}
			for _, rule := range network.Firewall.EgressRules {
				if !rule.IsAllow.IsTrue() {
					continue
				}
				if rule.Enforced.IsFalse() {
					continue
				}
				for _, destination := range rule.DestinationRanges {
					if cidr.IsPublic(destination.Value()) && cidr.CountAddresses(destination.Value()) > 1 {
						results.Add(
							"Firewall rule allows egress traffic to multiple addresses on the public internet.",
							destination,
						)
					} else {
						results.AddPassed(destination)
					}
				}
			}
		}
		return
	},
)
