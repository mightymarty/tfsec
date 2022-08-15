package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoOrgLevelServiceAccountImpersonation = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0009",
		Provider:    providers2.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-org-level-service-account-impersonation",
		Summary:     "Users should not be granted service account access at the organization level",
		Impact:      "Privilege escalation, impersonation of any/all services",
		Resolution:  "Provide access at the service-level instead of organization-level, if required",
		Explanation: `Users with service account access at organization level can impersonate any service account. Instead, they should be given access to particular service accounts as required.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/impersonating-service-accounts",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoOrgLevelServiceAccountImpersonationGoodExamples,
			BadExamples:         terraformNoOrgLevelServiceAccountImpersonationBadExamples,
			Links:               terraformNoOrgLevelServiceAccountImpersonationLinks,
			RemediationMarkdown: terraformNoOrgLevelServiceAccountImpersonationRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, org := range s.Google.IAM.Organizations {
			for _, member := range org.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at organization level.",
						member.Role,
					)
				} else {
					results.AddPassed(&member)
				}

			}
			for _, binding := range org.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if binding.Role.IsOneOf("roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator") {
					results.Add(
						"Service account access is granted to a user at organization level.",
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
