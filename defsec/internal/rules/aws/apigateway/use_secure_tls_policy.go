package apigateway

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0005",
		Provider:    providers2.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "API Gateway domain name uses outdated SSL/TLS protocols.",
		Impact:      "Outdated SSL policies increase exposure to known vulnerabilities",
		Resolution:  "Use the most modern TLS/SSL policies available",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links: []string{
			"https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, domain := range s.AWS.APIGateway.V1.DomainNames {
			if domain.SecurityPolicy.NotEqualTo("TLS_1_2") {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					domain.SecurityPolicy,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		for _, domain := range s.AWS.APIGateway.V2.DomainNames {
			if domain.SecurityPolicy.NotEqualTo("TLS_1_2") {
				results.Add(
					"Domain name is configured with an outdated TLS policy.",
					domain.SecurityPolicy,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
