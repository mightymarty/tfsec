package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEncryptInTransitData = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0015",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "encrypt-in-transit-data",
		Summary:     "SSL connections to a SQL database instance should be enforced.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enforce SSL for all connections",
		Explanation: `In-transit data should be encrypted so that if traffic is intercepted data will not be exposed in plaintext to attackers.`,
		Links: []string{
			"https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEncryptInTransitDataGoodExamples,
			BadExamples:         terraformEncryptInTransitDataBadExamples,
			Links:               terraformEncryptInTransitDataLinks,
			RemediationMarkdown: terraformEncryptInTransitDataRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.Settings.IPConfiguration.RequireTLS.IsFalse() {
				results.Add(
					"Database instance does not require TLS for all connections.",
					instance.Settings.IPConfiguration.RequireTLS,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
