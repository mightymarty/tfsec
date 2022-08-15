package spaces

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckDisableForceDestroy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0009",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "spaces",
		ShortCode:   "disable-force-destroy",
		Summary:     "Force destroy is enabled on Spaces bucket which is dangerous",
		Impact:      "Accidental deletion of bucket objects",
		Resolution:  "Don't use force destroy on bucket configuration",
		Explanation: `Enabling force destroy on a Spaces bucket means that the bucket can be deleted without the additional check that it is empty. This risks important data being accidentally deleted by a bucket removal process.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformDisableForceDestroyGoodExamples,
			BadExamples:         terraformDisableForceDestroyBadExamples,
			Links:               terraformDisableForceDestroyLinks,
			RemediationMarkdown: terraformDisableForceDestroyRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.DigitalOcean.Spaces.Buckets {
			if bucket.IsUnmanaged() {
				continue
			}
			if bucket.ForceDestroy.IsTrue() {
				results.Add(
					"Bucket has force-destroy enabled.",
					bucket.ForceDestroy,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
