package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableStateMachineTracing = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0117",
		Provider:    providers2.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-state-machine-tracing",
		Summary:     "SAM State machine must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all state machine activities.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-tracing",
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableStateMachineTracingGoodExamples,
			BadExamples:         cloudFormationEnableStateMachineTracingBadExamples,
			Links:               cloudFormationEnableStateMachineTracingLinks,
			RemediationMarkdown: cloudFormationEnableStateMachineTracingRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, stateMachine := range s.AWS.SAM.StateMachines {
			if stateMachine.IsUnmanaged() {
				continue
			}

			if stateMachine.Tracing.Enabled.IsFalse() {
				results.Add(
					"X-Ray tracing is not enabled,",
					stateMachine.Tracing.Enabled,
				)
			} else {
				results.AddPassed(&stateMachine)
			}
		}
		return
	},
)
