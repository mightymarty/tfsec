package sql

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0017",
		Provider:    providers2.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-public-access",
		Summary:     "Ensure that Cloud SQL Database Instances are not publicly exposed",
		Impact:      "Public exposure of sensitive data",
		Resolution:  "Remove public access from database instances",
		Explanation: `Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/gcp/CloudSQL/publicly-accessible-cloud-sql-instances.html",
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
		for _, instance := range s.Google.SQL.Instances {
			if instance.IsUnmanaged() {
				continue
			}
			if instance.Settings.IPConfiguration.EnableIPv4.IsTrue() {
				results.Add(
					"Database instance is granted a public internet address.",
					instance.Settings.IPConfiguration.EnableIPv4,
				)
			}
			for _, network := range instance.Settings.IPConfiguration.AuthorizedNetworks {
				if cidr.IsPublic(network.CIDR.Value()) {
					results.Add(
						"Database instance allows access from the public internet.",
						network.CIDR,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		return
	},
)
