package actions

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPlainTextActionEnvironmentSecrets = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-GIT-0002",
		Provider:   providers2.GitHubProvider,
		Service:    "actions",
		ShortCode:  "no-plain-text-action-secrets",
		Summary:    "Ensure plaintext value is not used for GitHub Action Environment Secret.",
		Impact:     "Unencrypted sensitive plaintext value can be easily accessible in code.",
		Resolution: "Do not store plaintext values in your code but rather populate the encrypted_value using fields from a resource, data source or variable.", Explanation: `For the purposes of security, the contents of the plaintext_value field have been marked as sensitive to Terraform, but this does not hide it from state files. State should be treated as sensitive always.`,

		Links: []string{
			"https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_environment_secret",
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPlainTextActionSecretsGoodExamples,
			BadExamples:         terraformNoPlainTextActionSecretsBadExamples,
			Links:               terraformNoPlainTextActionSecretsLinks,
			RemediationMarkdown: terraformNoPlainTextActionSecretsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, environmentSecret := range s.GitHub.EnvironmentSecrets {
			if environmentSecret.IsUnmanaged() {
				continue
			}
			if environmentSecret.PlainTextValue.IsNotEmpty() {
				results.Add("Secret has plain text value",
					environmentSecret.PlainTextValue)
			} else {
				results.AddPassed(&environmentSecret)
			}
		}
		return results
	},
)
