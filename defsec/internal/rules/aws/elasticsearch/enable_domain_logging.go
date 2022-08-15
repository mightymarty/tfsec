package elasticsearch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableDomainLogging = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0042",
		Provider:   providers2.AWSProvider,
		Service:    "elastic-search",
		ShortCode:  "enable-domain-logging",
		Summary:    "Domain logging should be enabled for Elastic Search domains",
		Impact:     "Logging provides vital information about access and usage",
		Resolution: "Enable logging for ElasticSearch domains",
		Explanation: `Amazon ES exposes four Elasticsearch logs through Amazon CloudWatch Logs: error logs, search slow logs, index slow logs, and audit logs. 

Search slow logs, index slow logs, and error logs are useful for troubleshooting performance and stability issues. 

Audit logs track user activity for compliance purposes. 

All the logs are disabled by default.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableDomainLoggingGoodExamples,
			BadExamples:         terraformEnableDomainLoggingBadExamples,
			Links:               terraformEnableDomainLoggingLinks,
			RemediationMarkdown: terraformEnableDomainLoggingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableDomainLoggingGoodExamples,
			BadExamples:         cloudFormationEnableDomainLoggingBadExamples,
			Links:               cloudFormationEnableDomainLoggingLinks,
			RemediationMarkdown: cloudFormationEnableDomainLoggingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.LogPublishing.AuditEnabled.IsFalse() {
				results.Add(
					"Domain audit logging is not enabled.",
					domain.LogPublishing.AuditEnabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
