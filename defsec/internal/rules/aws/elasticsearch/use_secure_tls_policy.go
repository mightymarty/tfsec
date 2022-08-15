package elasticsearch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0126",
		Provider:    providers2.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "Elasticsearch domain endpoint is using outdated TLS policy.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationUseSecureTlsPolicyGoodExamples,
			BadExamples:         cloudFormationUseSecureTlsPolicyBadExamples,
			Links:               cloudFormationUseSecureTlsPolicyLinks,
			RemediationMarkdown: cloudFormationUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.Endpoint.TLSPolicy.NotEqualTo("Policy-Min-TLS-1-2-2019-07") {
				results.Add(
					"Domain does not have a secure TLS policy.",
					domain.Endpoint.TLSPolicy,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
