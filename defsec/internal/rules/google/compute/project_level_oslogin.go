package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckProjectLevelOslogin = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0042",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "project-level-oslogin",
		Summary:     "OS Login should be enabled at project level",
		Impact:      "Access via SSH key cannot be revoked automatically when an IAM user is removed.",
		Resolution:  "Enable OS Login at project level",
		Explanation: `OS Login automatically revokes the relevant SSH keys when an IAM user has their access revoked.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformProjectLevelOsloginGoodExamples,
			BadExamples:         terraformProjectLevelOsloginBadExamples,
			Links:               terraformProjectLevelOsloginLinks,
			RemediationMarkdown: terraformProjectLevelOsloginRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		if s.Google.Compute.ProjectMetadata.IsManaged() {
			if s.Google.Compute.ProjectMetadata.EnableOSLogin.IsFalse() {
				results.Add(
					"OS Login is disabled at project level.",
					s.Google.Compute.ProjectMetadata.EnableOSLogin,
				)
			} else {
				results.AddPassed(&s.Google.Compute.ProjectMetadata)
			}
		}
		return
	},
)
