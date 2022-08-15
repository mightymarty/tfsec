package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicIngress = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0001",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "no-public-ingress",
		Summary:     "The firewall has an inbound rule with open access",
		Impact:      "Your port is exposed to the internet",
		Resolution:  "Set a more restrictive CIRDR range",
		Explanation: `Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, firewall := range s.DigitalOcean.Compute.Firewalls {
			var failed bool
			for _, rule := range firewall.InboundRules {
				for _, address := range rule.SourceAddresses {
					if cidr.IsPublic(address.Value()) && cidr.CountAddresses(address.Value()) > 1 {
						failed = true
						results.Add(
							"Ingress rule allows access from multiple public addresses.",
							address,
						)
					}
				}
			}
			if !failed {
				results.AddPassed(&firewall)
			}
		}
		return
	},
)
