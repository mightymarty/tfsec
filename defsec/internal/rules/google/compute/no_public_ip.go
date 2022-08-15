package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckInstancesDoNotHavePublicIPs = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0031",
		Provider:    providers2.GoogleProvider,
		Service:     service,
		ShortCode:   "no-public-ip",
		Summary:     "Instances should not have public IP addresses",
		Impact:      "Direct exposure of an instance to the public internet",
		Resolution:  "Remove public IP",
		Explanation: `Instances should not be publicly exposed to the internet`,
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIpGoodExamples,
			BadExamples:         terraformNoPublicIpBadExamples,
			Links:               terraformNoPublicIpLinks,
			RemediationMarkdown: terraformNoPublicIpRemediationMarkdown,
		},
		Severity: severity2.High,
		Links: []string{
			"https://cloud.google.com/compute/docs/ip-addresses#externaladdresses",
		},
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.HasPublicIP.IsTrue() {
					results.Add(
						"Instance has a public IP allocated.",
						networkInterface.HasPublicIP,
					)
				} else {
					results.AddPassed(&networkInterface)
				}
			}

		}
		return results
	},
)
