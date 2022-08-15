package storage

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableUbla = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0002",
		Provider:    providers2.GoogleProvider,
		Service:     "storage",
		ShortCode:   "enable-ubla",
		Summary:     "Ensure that Cloud Storage buckets have uniform bucket-level access enabled",
		Impact:      "ACLs are difficult to manage and often lead to incorrect/unintended configurations.",
		Resolution:  "Enable uniform bucket level access to provide a uniform permissioning system.",
		Explanation: `When you enable uniform bucket-level access on a bucket, Access Control Lists (ACLs) are disabled, and only bucket-level Identity and Access Management (IAM) permissions grant access to that bucket and the objects it contains. You revoke all access granted by object ACLs and the ability to administrate permissions using bucket ACLs.`,
		Links: []string{
			"https://cloud.google.com/storage/docs/uniform-bucket-level-access",
			"https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableUblaGoodExamples,
			BadExamples:         terraformEnableUblaBadExamples,
			Links:               terraformEnableUblaLinks,
			RemediationMarkdown: terraformEnableUblaRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.Google.Storage.Buckets {
			if bucket.IsUnmanaged() {
				continue
			}
			if bucket.EnableUniformBucketLevelAccess.IsFalse() {
				results.Add(
					"Bucket has uniform bucket level access disabled.",
					bucket.EnableUniformBucketLevelAccess,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return
	},
)
