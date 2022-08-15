package spaces

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckVersioningEnabled = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-DIG-0007",
		Provider:    providers2.DigitalOceanProvider,
		Service:     "spaces",
		ShortCode:   "versioning-enabled",
		Summary:     "Spaces buckets should have versioning enabled",
		Impact:      "Deleted or modified data would not be recoverable",
		Resolution:  "Enable versioning to protect against accidental or malicious removal or modification",
		Explanation: `Versioning is a means of keeping multiple variants of an object in the same bucket. You can use the Spaces (S3) Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. With versioning you can recover more easily from both unintended user actions and application failures.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformVersioningEnabledGoodExamples,
			BadExamples:         terraformVersioningEnabledBadExamples,
			Links:               terraformVersioningEnabledLinks,
			RemediationMarkdown: terraformVersioningEnabledRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.DigitalOcean.Spaces.Buckets {
			if bucket.IsUnmanaged() {
				continue
			}
			if bucket.Versioning.Enabled.IsFalse() {
				results.Add(
					"Bucket does not have versioning enabled.",
					bucket.Versioning.Enabled,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
