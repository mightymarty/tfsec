package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableApiTracing = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0111",
		Provider:    providers2.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-api-tracing",
		Summary:     "SAM API must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-api.html#sam-api-tracingenabled",
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableApiTracingGoodExamples,
			BadExamples:         cloudFormationEnableApiTracingBadExamples,
			Links:               cloudFormationEnableApiTracingLinks,
			RemediationMarkdown: cloudFormationEnableApiTracingRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.IsUnmanaged() {
				continue
			}

			if api.TracingEnabled.IsFalse() {
				results.Add(
					"X-Ray tracing is not enabled,",
					api.TracingEnabled,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
