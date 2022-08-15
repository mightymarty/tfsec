package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	"strings"
)

var CheckNoPrivilegedServiceAccounts = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0007",
		Provider:    providers2.GoogleProvider,
		Service:     "iam",
		ShortCode:   "no-privileged-service-accounts",
		Summary:     "Service accounts should not have roles assigned with excessive privileges",
		Impact:      "Cloud account takeover if a resource using a service account is compromised",
		Resolution:  "Limit service account access to minimal required set",
		Explanation: `Service accounts should have a minimal set of permissions assigned in order to do their job. They should never have excessive access as if compromised, an attacker can escalate privileges and take over the entire account.`,
		Links: []string{
			"https://cloud.google.com/iam/docs/understanding-roles",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPrivilegedServiceAccountsGoodExamples,
			BadExamples:         terraformNoPrivilegedServiceAccountsBadExamples,
			Links:               terraformNoPrivilegedServiceAccountsLinks,
			RemediationMarkdown: terraformNoPrivilegedServiceAccountsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, project := range s.Google.IAM.AllProjects() {
			for _, member := range project.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					} else {
						results.AddPassed(&member)
					}

				}
			}
			for _, binding := range project.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						} else {
							results.AddPassed(&binding)
						}

					}
				}
			}
		}
		for _, folder := range s.Google.IAM.AllFolders() {
			for _, member := range folder.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					} else {
						results.AddPassed(&member)
					}

				}
			}
			for _, binding := range folder.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						} else {
							results.AddPassed(member)
						}

					}
				}
			}

		}

		for _, org := range s.Google.IAM.Organizations {
			for _, member := range org.Members {
				if member.IsUnmanaged() {
					continue
				}
				if member.Member.StartsWith("serviceAccount:") {
					if isRolePrivileged(member.Role.Value()) {
						results.Add(
							"Service account is granted a privileged role.",
							member.Role,
						)
					} else {
						results.AddPassed(&member)
					}

				}
			}
			for _, binding := range org.Bindings {
				if binding.IsUnmanaged() {
					continue
				}
				if isRolePrivileged(binding.Role.Value()) {
					for _, member := range binding.Members {
						if member.StartsWith("serviceAccount:") {
							results.Add(
								"Service account is granted a privileged role.",
								binding.Role,
							)
						} else {
							results.AddPassed(member)
						}

					}
				}
			}

		}

		return
	},
)

func isRolePrivileged(role string) bool {
	switch {
	case role == "roles/owner":
		return true
	case role == "roles/editor":
		return true
	case strings.HasSuffix(strings.ToLower(role), "admin"):
		return true
	}
	return false
}
