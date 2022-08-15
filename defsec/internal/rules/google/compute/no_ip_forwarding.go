package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoIpForwarding = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0043",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-ip-forwarding",
		Summary:     "Instances should not have IP forwarding enabled",
		Impact:      "Instance can send/receive packets without the explicit instance address",
		Resolution:  "Disable IP forwarding",
		Explanation: `Disabling IP forwarding ensures the instance can only receive packets addressed to the instance and can only send packets with a source address of the instance.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoIpForwardingGoodExamples,
			BadExamples:         terraformNoIpForwardingBadExamples,
			Links:               terraformNoIpForwardingLinks,
			RemediationMarkdown: terraformNoIpForwardingRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.CanIPForward.IsTrue() {
				results.Add(
					"Instance has IP forwarding allowed.",
					instance.CanIPForward,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
