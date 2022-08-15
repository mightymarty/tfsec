package apigateway

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableTracing = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0003",
		Provider:    providers2.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-tracing",
		Summary:     "API Gateway must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableTracingGoodExamples,
			BadExamples:         terraformEnableTracingBadExamples,
			Links:               terraformEnableTracingLinks,
			RemediationMarkdown: terraformEnableTracingRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.IsUnmanaged() {
				continue
			}
			for _, stage := range api.Stages {
				if stage.IsUnmanaged() {
					continue
				}
				if stage.XRayTracingEnabled.IsFalse() {
					results.Add(
						"X-Ray tracing is not enabled,",
						stage.XRayTracingEnabled,
					)
				} else {
					results.AddPassed(&stage)
				}
			}
		}
		return
	},
)
