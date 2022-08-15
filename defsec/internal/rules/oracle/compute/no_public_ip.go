package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicIp = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-OCI-0001",
		Provider:   providers2.OracleProvider,
		Service:    "compute",
		ShortCode:  "no-public-ip",
		Summary:    "Compute instance requests an IP reservation from a public pool",
		Impact:     "The compute instance has the ability to be reached from outside",
		Resolution: "Reconsider the use of an public IP",
		Explanation: `Compute instance requests an IP reservation from a public pool

The compute instance has the ability to be reached from outside, you might want to sonder the use of a non public IP.`,
		Links: []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIpGoodExamples,
			BadExamples:         terraformNoPublicIpBadExamples,
			Links:               terraformNoPublicIpLinks,
			RemediationMarkdown: terraformNoPublicIpRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, reservation := range s.Oracle.Compute.AddressReservations {
			if reservation.IsUnmanaged() {
				continue
			}
			if reservation.Pool.EqualTo("public-ippool") { // TODO: future improvement: we need to see what this IP is used for before flagging
				results.Add(
					"Reservation made for public IP address.",
					reservation.Pool,
				)
			} else {
				results.AddPassed(reservation)
			}
		}
		return
	},
)
