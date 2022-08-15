package apigateway

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	v12 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v1"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0004",
		Provider:    providers2.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "no-public-access",
		Summary:     "No unauthorized access to API Gateway methods",
		Impact:      "API gateway methods can be accessed without authorization.",
		Resolution:  "Use and authorization method or require API Key",
		Explanation: `API Gateway methods should generally be protected by authorization or api key. OPTION verb calls can be used without authorization`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.IsUnmanaged() {
				continue
			}
			for _, resource := range api.Resources {
				for _, method := range resource.Methods {
					if method.HTTPMethod.EqualTo("OPTION") {
						continue
					}
					if method.APIKeyRequired.IsTrue() {
						continue
					}
					if method.AuthorizationType.EqualTo(v12.AuthorizationNone) {
						results.Add(
							"Authorization is not enabled for this method.",
							method.AuthorizationType,
						)
					} else {
						results.AddPassed(&method)
					}
				}
			}
		}
		return
	},
)
