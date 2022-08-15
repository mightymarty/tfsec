package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoProjectWideSshKeys = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0030",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-project-wide-ssh-keys",
		Summary:     "Disable project-wide SSH keys for all instances",
		Impact:      "Compromise of a single key pair compromises all instances",
		Resolution:  "Disable project-wide SSH keys",
		Explanation: `Use of project-wide SSH keys means that a compromise of any one of these key pairs can result in all instances being compromised. It is recommended to use instance-level keys.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoProjectWideSshKeysGoodExamples,
			BadExamples:         terraformNoProjectWideSshKeysBadExamples,
			Links:               terraformNoProjectWideSshKeysLinks,
			RemediationMarkdown: terraformNoProjectWideSshKeysRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.EnableProjectSSHKeyBlocking.IsFalse() {
				results.Add(
					"Instance allows use of project-level SSH keys.",
					instance.EnableProjectSSHKeyBlocking,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
