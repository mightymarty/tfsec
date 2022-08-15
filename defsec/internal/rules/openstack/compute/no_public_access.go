package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-OPNSTK-0002",
		Provider:    providers2.OpenStackProvider,
		Service:     "compute",
		ShortCode:   "no-public-access",
		Summary:     "A firewall rule allows traffic from/to the public internet",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Employ more restrictive firewall rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, rule := range s.OpenStack.Compute.Firewall.AllowRules {
			if rule.IsUnmanaged() {
				continue
			}
			if rule.Enabled.IsFalse() {
				continue
			}
			if rule.Destination.IsEmpty() {
				results.Add(
					"Firewall rule does not restrict destination address internally.",
					rule.Destination,
				)
			} else if cidr.IsPublic(rule.Destination.Value()) {
				results.Add(
					"Firewall rule allows public egress.",
					rule.Destination,
				)
			} else if rule.Source.IsEmpty() {
				results.Add(
					"Firewall rule does not restrict source address internally.",
					rule.Source,
				)
			} else if cidr.IsPublic(rule.Source.Value()) {
				results.Add(
					"Firewall rule allows public ingress.",
					rule.Source,
				)
			} else {
				results.AddPassed(rule)
			}

		}
		return
	},
)
