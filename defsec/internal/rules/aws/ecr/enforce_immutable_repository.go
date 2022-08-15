package ecr

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnforceImmutableRepository = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0031",
		Provider:   providers2.AWSProvider,
		Service:    "ecr",
		ShortCode:  "enforce-immutable-repository",
		Summary:    "ECR images tags shouldn't be mutable.",
		Impact:     "Image tags could be overwritten with compromised images",
		Resolution: "Only use immutable images in ECR",
		Explanation: `ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>`,
		Links: []string{
			"https://sysdig.com/blog/toctou-tag-mutability/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforceImmutableRepositoryGoodExamples,
			BadExamples:         terraformEnforceImmutableRepositoryBadExamples,
			Links:               terraformEnforceImmutableRepositoryLinks,
			RemediationMarkdown: terraformEnforceImmutableRepositoryRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnforceImmutableRepositoryGoodExamples,
			BadExamples:         cloudFormationEnforceImmutableRepositoryBadExamples,
			Links:               cloudFormationEnforceImmutableRepositoryLinks,
			RemediationMarkdown: cloudFormationEnforceImmutableRepositoryRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.ImageTagsImmutable.IsFalse() {
				results.Add(
					"Repository tags are mutable.",
					repo.ImageTagsImmutable,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)
