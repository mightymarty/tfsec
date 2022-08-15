package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoDefaultServiceAccount = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0044",
		Provider:    providers2.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-default-service-account",
		Summary:     "Instances should not use the default service account",
		Impact:      "Instance has full access to the project",
		Resolution:  "Remove use of default service account",
		Explanation: `The default service account has full project access. Instances should instead be assigned the minimal access they need.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoDefaultServiceAccountGoodExamples,
			BadExamples:         terraformNoDefaultServiceAccountBadExamples,
			Links:               terraformNoDefaultServiceAccountLinks,
			RemediationMarkdown: terraformNoDefaultServiceAccountRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.ServiceAccount.Email.IsEmpty() || instance.ServiceAccount.Email.EndsWith("-compute@developer.gserviceaccount.com") {
				results.Add(
					"Instance uses the default service account.",
					instance.ServiceAccount.Email,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
