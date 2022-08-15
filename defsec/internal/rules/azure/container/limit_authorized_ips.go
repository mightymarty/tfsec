package container

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckLimitAuthorizedIps = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0041",
		Provider:    providers2.AzureProvider,
		Service:     "container",
		ShortCode:   "limit-authorized-ips",
		Summary:     "Ensure AKS has an API Server Authorized IP Ranges enabled",
		Impact:      "Any IP can interact with the API server",
		Resolution:  "Limit the access to the API server to a limited IP range",
		Explanation: `The API server is the central way to interact with and manage a cluster. To improve cluster security and minimize attacks, the API server should only be accessible from a limited set of IP address ranges.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/aks/api-server-authorized-ip-ranges",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformLimitAuthorizedIpsGoodExamples,
			BadExamples:         terraformLimitAuthorizedIpsBadExamples,
			Links:               terraformLimitAuthorizedIpsLinks,
			RemediationMarkdown: terraformLimitAuthorizedIpsRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.EnablePrivateCluster.IsTrue() {
				continue
			}
			if len(cluster.APIServerAuthorizedIPRanges) == 0 {
				results.Add(
					"Cluster does not limit API access to specific IP addresses.",
					cluster.EnablePrivateCluster,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
