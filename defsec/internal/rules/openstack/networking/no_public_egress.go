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
		AVDID:       "AVD-OPNSTK-0004",
		Provider:    providers2.OpenStackProvider,
		Service:     "networking",
		ShortCode:   "no-public-egress",
		Summary:     "A security group rule allows egress traffic to multiple public addresses",
		Impact:      "Potential exfiltration of data to the public internet",
		Resolution:  "Employ more restrictive security group rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			Links:               terraformNoPublicEgressLinks,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.OpenStack.Networking.SecurityGroups {
			for _, rule := range group.Rules {
				if rule.IsUnmanaged() || rule.IsIngress.IsTrue() {
					continue
				}
				if cidr.IsPublic(rule.CIDR.Value()) && cidr.CountAddresses(rule.CIDR.Value()) > 1 {
					results.Add(
						"Security group rule allows egress to multiple public addresses.",
						rule.CIDR,
					)
				} else {
					results.AddPassed(rule)
				}
			}
		}
		return
	},
)
