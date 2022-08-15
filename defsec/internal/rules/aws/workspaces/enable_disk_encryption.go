package workspaces

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableDiskEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0109",
		Provider:    providers2.AWSProvider,
		Service:     "workspaces",
		ShortCode:   "enable-disk-encryption",
		Summary:     "Root and user volumes on Workspaces should be encrypted",
		Impact:      "Data can be freely read if compromised",
		Resolution:  "Root and user volume encryption should be enabled",
		Explanation: `Workspace volumes for both user and root should be encrypted to protect the data stored on them.`,
		Links: []string{
			"https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableDiskEncryptionGoodExamples,
			BadExamples:         terraformEnableDiskEncryptionBadExamples,
			Links:               terraformEnableDiskEncryptionLinks,
			RemediationMarkdown: terraformEnableDiskEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableDiskEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableDiskEncryptionBadExamples,
			Links:               cloudFormationEnableDiskEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableDiskEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, workspace := range s.AWS.WorkSpaces.WorkSpaces {
			var fail bool
			if workspace.RootVolume.Encryption.Enabled.IsFalse() {
				results.Add(
					"Root volume does not have encryption enabled.",
					workspace.RootVolume.Encryption.Enabled,
				)
				fail = true
			}
			if workspace.UserVolume.Encryption.Enabled.IsFalse() {
				results.Add(
					"User volume does not have encryption enabled.",
					workspace.UserVolume.Encryption.Enabled,
				)
				fail = true
			}
			if !fail {
				results.AddPassed(&workspace)
			}
		}
		return
	},
)
