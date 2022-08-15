package elasticsearch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnforceHttps = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0046",
		Provider:   providers2.AWSProvider,
		Service:    "elastic-search",
		ShortCode:  "enforce-https",
		Summary:    "Elasticsearch doesn't enforce HTTPS traffic.",
		Impact:     "HTTP traffic can be intercepted and the contents read",
		Resolution: "Enforce the use of HTTPS for ElasticSearch",
		Explanation: `Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.

You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-data-protection.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforceHttpsGoodExamples,
			BadExamples:         terraformEnforceHttpsBadExamples,
			Links:               terraformEnforceHttpsLinks,
			RemediationMarkdown: terraformEnforceHttpsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnforceHttpsGoodExamples,
			BadExamples:         cloudFormationEnforceHttpsBadExamples,
			Links:               cloudFormationEnforceHttpsLinks,
			RemediationMarkdown: cloudFormationEnforceHttpsRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.Endpoint.EnforceHTTPS.IsFalse() {
				results.Add(
					"Domain does not enforce HTTPS.",
					domain.Endpoint.EnforceHTTPS,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
