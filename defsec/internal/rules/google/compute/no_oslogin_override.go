package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoOsloginOverride = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0036",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-oslogin-override",
		Summary:     "Instances should not override the project setting for OS Login",
		Impact:      "Access via SSH key cannot be revoked automatically when an IAM user is removed.",
		Resolution:  "Enable OS Login at project level and remove instance-level overrides",
		Explanation: `OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoOsloginOverrideGoodExamples,
			BadExamples:         terraformNoOsloginOverrideBadExamples,
			Links:               terraformNoOsloginOverrideLinks,
			RemediationMarkdown: terraformNoOsloginOverrideRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.OSLoginEnabled.IsFalse() {
				results.Add(
					"Instance has OS Login disabled.",
					instance.OSLoginEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
