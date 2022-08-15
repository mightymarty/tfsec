package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPlaintextPassword = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-OPNSTK-0001",
		Provider:    providers2.OpenStackProvider,
		Service:     "compute",
		ShortCode:   "no-plaintext-password",
		Summary:     "No plaintext password for compute instance",
		Impact:      "Including a plaintext password could lead to compromised instance",
		Resolution:  "Do not use plaintext passwords in terraform files",
		Explanation: `Assigning a password to the compute instance using plaintext could lead to compromise; it would be preferable to use key-pairs as a login mechanism`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPlaintextPasswordGoodExamples,
			BadExamples:         terraformNoPlaintextPasswordBadExamples,
			Links:               terraformNoPlaintextPasswordLinks,
			RemediationMarkdown: terraformNoPlaintextPasswordRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.OpenStack.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.AdminPassword.IsNotEmpty() {
				results.Add(
					"Instance has admin password set.",
					instance.AdminPassword,
				)
			} else {
				results.AddPassed(instance)
			}
		}
		return
	},
)
