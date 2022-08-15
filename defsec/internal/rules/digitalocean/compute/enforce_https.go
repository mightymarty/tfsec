package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnforceHttps = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-DIG-0002",
		Provider:   providers2.DigitalOceanProvider,
		Service:    "compute",
		ShortCode:  "enforce-https",
		Summary:    "The load balancer forwarding rule is using an insecure protocol as an entrypoint",
		Impact:     "Your inbound traffic is not protected",
		Resolution: "Switch to HTTPS to benefit from TLS security features",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/load-balancers/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforceHttpsGoodExamples,
			BadExamples:         terraformEnforceHttpsBadExamples,
			Links:               terraformEnforceHttpsLinks,
			RemediationMarkdown: terraformEnforceHttpsRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, lb := range s.DigitalOcean.Compute.LoadBalancers {
			for _, rule := range lb.ForwardingRules {
				if rule.EntryProtocol.EqualTo("http") {
					results.Add(
						"Load balancer has aforwarding rule which uses HTTP instead of HTTPS.",
						rule.EntryProtocol,
					)
				} else {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
