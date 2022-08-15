package network

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckDisableRdpFromInternet = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0048",
		Provider:   providers2.AzureProvider,
		Service:    "network",
		ShortCode:  "disable-rdp-from-internet",
		Summary:    "RDP access should not be accessible from the Internet, should be blocked on port 3389",
		Impact:     "Anyone from the internet can potentially RDP onto an instance",
		Resolution: "Block RDP port from internet",
		Explanation: `RDP access can be configured on either the network security group or in the network security group rule.

RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformDisableRdpFromInternetGoodExamples,
			BadExamples:         terraformDisableRdpFromInternetBadExamples,
			Links:               terraformDisableRdpFromInternetLinks,
			RemediationMarkdown: terraformDisableRdpFromInternetRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.Azure.Network.SecurityGroups {
			var failed bool
			for _, rule := range group.Rules {
				if rule.Allow.IsFalse() || rule.Outbound.IsTrue() {
					continue
				}
				if rule.Protocol.EqualTo("Icmp", types.IgnoreCase) {
					continue
				}
				for _, ports := range rule.DestinationPorts {
					if ports.Includes(3389) {
						for _, ip := range rule.SourceAddresses {
							if cidr.IsPublic(ip.Value()) && cidr.CountAddresses(ip.Value()) > 1 {
								failed = true
								results.Add(
									"Security group rule allows ingress to RDP port from multiple public internet addresses.",
									ip,
								)
							}
						}
					}
				}
				if !failed {
					results.AddPassed(&group)
				}
			}
		}
		return
	},
)
