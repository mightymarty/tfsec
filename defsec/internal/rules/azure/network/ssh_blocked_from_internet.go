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

var CheckSshBlockedFromInternet = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0050",
		Provider:   providers2.AzureProvider,
		Service:    "network",
		ShortCode:  "ssh-blocked-from-internet",
		Summary:    "SSH access should not be accessible from the Internet, should be blocked on port 22",
		Impact:     "Its dangerous to allow SSH access from the internet",
		Resolution: "Block port 22 access from the internet",
		Explanation: `SSH access can be configured on either the network security group or in the network security group rule. 

SSH access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any)`,
		Links: []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSshBlockedFromInternetGoodExamples,
			BadExamples:         terraformSshBlockedFromInternetBadExamples,
			Links:               terraformSshBlockedFromInternetLinks,
			RemediationMarkdown: terraformSshBlockedFromInternetRemediationMarkdown,
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
					if ports.Includes(22) {
						for _, ip := range rule.SourceAddresses {
							if cidr.IsPublic(ip.Value()) && cidr.CountAddresses(ip.Value()) > 1 {
								failed = true
								results.Add(
									"Security group rule allows ingress to SSH port from multiple public internet addresses.",
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
