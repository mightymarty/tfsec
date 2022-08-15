package database

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckAllThreatAlertsEnabled = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0028",
		Provider:    providers2.AzureProvider,
		Service:     "database",
		ShortCode:   "all-threat-alerts-enabled",
		Summary:     "No threat detections are set",
		Impact:      "Disabling threat alerts means you are not getting the full benefit of server security protection",
		Resolution:  "Use all provided threat alerts",
		Explanation: `SQL Server can alert for security issues including SQL Injection, vulnerabilities, access anomalies and data exfiltration. Ensure none of these are disabled to benefit from the best protection`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAllThreatAlertsEnabledGoodExamples,
			BadExamples:         terraformAllThreatAlertsEnabledBadExamples,
			Links:               terraformAllThreatAlertsEnabledLinks,
			RemediationMarkdown: terraformAllThreatAlertsEnabledRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.SecurityAlertPolicies {
				if len(policy.DisabledAlerts) > 0 {
					results.Add(
						"Server has a security alert policy which disables alerts.",
						policy.DisabledAlerts[0],
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
