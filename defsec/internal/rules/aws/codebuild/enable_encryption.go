package codebuild

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0018",
		Provider:    providers2.AWSProvider,
		Service:     "codebuild",
		ShortCode:   "enable-encryption",
		Summary:     "CodeBuild Project artifacts encryption should not be disabled",
		Impact:      "CodeBuild project artifacts are unencrypted",
		Resolution:  "Enable encryption for CodeBuild project artifacts",
		Explanation: `All artifacts produced by your CodeBuild project pipeline should always be encrypted`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableEncryptionGoodExamples,
			BadExamples:         terraformEnableEncryptionBadExamples,
			Links:               terraformEnableEncryptionLinks,
			RemediationMarkdown: terraformEnableEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableEncryptionBadExamples,
			Links:               cloudFormationEnableEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, project := range s.AWS.CodeBuild.Projects {
			if project.ArtifactSettings.EncryptionEnabled.IsFalse() {
				results.Add(
					"Encryption is not enabled for project artifacts.",
					project.ArtifactSettings.EncryptionEnabled,
				)
			} else {
				results.AddPassed(&project)
			}

			for _, setting := range project.SecondaryArtifactSettings {
				if setting.EncryptionEnabled.IsFalse() {
					results.Add(
						"Encryption is not enabled for secondary project artifacts.",
						setting.EncryptionEnabled,
					)
				} else {
					results.AddPassed(&setting)
				}
			}

		}
		return
	},
)
