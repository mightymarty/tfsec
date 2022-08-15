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
		AVDID:       "AVD-OPNSTK-0003",
		Provider:    providers2.OpenStackProvider,
		Service:     "networking",
		ShortCode:   "no-public-ingress",
		Summary:     "A security group rule allows ingress traffic from multiple public addresses",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Employ more restrictive security group rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.OpenStack.Networking.SecurityGroups {
			for _, rule := range group.Rules {
				if rule.IsUnmanaged() || rule.IsIngress.IsFalse() {
					continue
				}
				if cidr.IsPublic(rule.CIDR.Value()) && cidr.CountAddresses(rule.CIDR.Value()) > 1 {
					results.Add(
						"Security group rule allows ingress from multiple public addresses.",
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
