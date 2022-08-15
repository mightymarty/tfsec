package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAudit = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0027",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "enable-audit",
		Summary:     "Auditing should be enabled on Azure SQL Databases",
		Impact:      "Auditing provides valuable information about access and usage",
		Resolution:  "Enable auditing on Azure SQL databases",
		Explanation: `Auditing helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAuditGoodExamples,
			BadExamples:         terraformEnableAuditBadExamples,
			Links:               terraformEnableAuditLinks,
			RemediationMarkdown: terraformEnableAuditRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			if len(server.ExtendedAuditingPolicies) == 0 && server.IsManaged() {
				results.Add(
					"Server does not have an extended audit policy configured.",
					&server,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
