package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoFolderLevelServiceAccountImpersonation = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0005",
		Provider:    providers2.GoogleProvider,
		Service:     "IAM",
		ShortCode:   "no-folder-level-service-account-impersonation",
		Summary:     "Users should not be granted service account access at the folder level",
		Impact:      "Privilege escalation, impersonation of any/all services",
		Resolution:  "Provide access at the service-level instead of folder-level, if required",
		Explanation: `Users with service account access at folder level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoFolderLevelServiceAccountImpersonationGoodExamples,
			BadExamples:         terraformNoFolderLevelServiceAccountImpersonationBadExamples,
			Links:               terraformNoFolderLevelServiceAccountImpersonationLinks,
			RemediationMarkdown: terraformNoFolderLevelServiceAccountImpersonationRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, folder := range s.Google.IAM.AllFolders() {
			for _, member := range folder.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at folder level.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range folder.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if binding.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at folder level.",
						binding.Role,
					)
				} else {
					results.AddPassed(&binding)
				}

			}
		}
		return
	},
)
