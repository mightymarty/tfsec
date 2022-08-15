package keyvault

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckSpecifyNetworkAcl = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0013",
		Provider:   providers2.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "specify-network-acl",
		Summary:    "Key vault should have the network acl block specified",
		Impact:     "Without a network ACL the key vault is freely accessible",
		Resolution: "Set a network ACL for the key vault",
		Explanation: `Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. 

The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/general/network-security",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformSpecifyNetworkAclGoodExamples,
			BadExamples:         terraformSpecifyNetworkAclBadExamples,
			Links:               terraformSpecifyNetworkAclLinks,
			RemediationMarkdown: terraformSpecifyNetworkAclRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			if vault.IsUnmanaged() {
				continue
			}
			if vault.NetworkACLs.DefaultAction.NotEqualTo("Deny") {
				results.Add(
					"Vault network ACL does not block access by default.",
					vault.NetworkACLs.DefaultAction,
				)
			} else {
				results.AddPassed(&vault)
			}
		}
		return
	},
)
