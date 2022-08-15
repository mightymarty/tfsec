package storage

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckQueueServicesLoggingEnabled = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AZU-0009",
		Provider:   providers2.AzureProvider,
		Service:    "storage",
		ShortCode:  "queue-services-logging-enabled",
		Summary:    "When using Queue Services for a storage account, logging should be enabled.",
		Impact:     "Logging provides valuable information about access and usage",
		Resolution: "Enable logging for Queue Services",
		Explanation: `Storage Analytics logs detailed information about successful and failed requests to a storage service. 

This information can be used to monitor individual requests and to diagnose issues with a storage service. 

Requests are logged on a best-effort basis.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging?tabs=dotnet",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformQueueServicesLoggingEnabledGoodExamples,
			BadExamples:         terraformQueueServicesLoggingEnabledBadExamples,
			Links:               terraformQueueServicesLoggingEnabledLinks,
			RemediationMarkdown: terraformQueueServicesLoggingEnabledRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, account := range s.Azure.Storage.Accounts {
			if account.IsUnmanaged() {
				continue
			}
			if account.QueueProperties.EnableLogging.IsFalse() {
				results.Add(
					"Queue services storage account does not have logging enabled.",
					account.QueueProperties.EnableLogging,
				)
			} else {
				results.AddPassed(&account)
			}
		}
		return
	},
)
