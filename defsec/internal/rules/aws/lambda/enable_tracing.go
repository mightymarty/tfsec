package lambda

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	lambda2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/lambda"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableTracing = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0066",
		Provider:    providers2.AWSProvider,
		Service:     "lambda",
		ShortCode:   "enable-tracing",
		Summary:     "Lambda functions should have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all function activity. This will allow for identifying bottlenecks, slow downs and timeouts.`,
		Links: []string{
			"https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableTracingGoodExamples,
			BadExamples:         terraformEnableTracingBadExamples,
			Links:               terraformEnableTracingLinks,
			RemediationMarkdown: terraformEnableTracingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableTracingGoodExamples,
			BadExamples:         cloudFormationEnableTracingBadExamples,
			Links:               cloudFormationEnableTracingLinks,
			RemediationMarkdown: cloudFormationEnableTracingRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, function := range s.AWS.Lambda.Functions {
			if function.IsUnmanaged() {
				continue
			}
			if function.Tracing.Mode.NotEqualTo(lambda2.TracingModeActive) {
				results.Add(
					"Function does not have tracing enabled.",
					function.Tracing.Mode,
				)
			} else {
				results.AddPassed(&function)
			}
		}
		return
	},
)
