package repositories

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckPrivate = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-GIT-0001",
		Provider:   providers2.GitHubProvider,
		Service:    "repositories",
		ShortCode:  "private",
		Summary:    "Github repository shouldn't be public.",
		Impact:     "Anyone can read the contents of the GitHub repository and leak IP",
		Resolution: "Make sensitive or commercially important repositories private",
		Explanation: `Github repository should be set to be private.

You can do this by either setting <code>private</code> attribute to 'true' or <code>visibility</code> attribute to 'internal' or 'private'.`,
		Links: []string{
			"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility",
			"https://docs.github.com/en/github/creating-cloning-and-archiving-repositories/about-repository-visibility#about-internal-repositories",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformPrivateGoodExamples,
			BadExamples:         terraformPrivateBadExamples,
			Links:               terraformPrivateLinks,
			RemediationMarkdown: terraformPrivateRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, repo := range s.GitHub.Repositories {
			if repo.IsUnmanaged() {
				continue
			}
			if repo.Public.IsTrue() {
				results.Add(
					"Repository is public,",
					repo.Public,
				)
			} else {
				results.AddPassed(repo)
			}
		}
		return
	},
)
