package storage

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	storage2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/storage"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0007",
		Provider:   providers2.AzureProvider,
		Service:    "storage",
		ShortCode:  "no-public-access",
		Summary:    "Storage containers in blob storage mode should not have public access",
		Impact:     "Data in the storage container could be exposed publicly",
		Resolution: "Disable public access to storage containers",
		Explanation: `Storage container public access should be off. It can be configured for blobs only, containers and blobs or off entirely. The default is off, with no public access.

Explicitly overriding publicAccess to anything other than off should be avoided.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal#set-the-public-access-level-for-a-container",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			for _, container := range account.Containers {
				if container.PublicAccess.NotEqualTo(storage2.PublicAccessOff) {
					results.Add(
						"Container allows public access.",
						container.PublicAccess,
					)
				} else {
					results.AddPassed(&container)
				}
			}
		}
		return
	},
)
