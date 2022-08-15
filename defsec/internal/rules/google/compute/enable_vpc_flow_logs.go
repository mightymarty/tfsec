package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableVPCFlowLogs = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0029",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-vpc-flow-logs",
		Summary:     "VPC flow logs should be enabled for all subnetworks",
		Impact:      "Limited auditing capability and awareness",
		Resolution:  "Enable VPC flow logs",
		Explanation: `VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableVpcFlowLogsGoodExamples,
			BadExamples:         terraformEnableVpcFlowLogsBadExamples,
			Links:               terraformEnableVpcFlowLogsLinks,
			RemediationMarkdown: terraformEnableVpcFlowLogsRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, network := range s.Google.Compute.Networks {
			for _, subnetwork := range network.Subnetworks {
				if subnetwork.EnableFlowLogs.IsFalse() {
					results.Add(
						"Subnetwork does not have VPC flow logs enabled.",
						subnetwork.EnableFlowLogs,
					)
				} else {
					results.AddPassed(&subnetwork)
				}
			}
		}
		return
	},
)
