package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableStateMachineLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0119",
		Provider:    providers2.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-state-machine-logging",
		Summary:     "SAM State machine must have logging enabled",
		Impact:      "Without logging enabled it is difficult to identify suspicious activity",
		Resolution:  "Enable logging",
		Explanation: `Logging enables end-to-end debugging and analysis of all state machine activities.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-logging",
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, stateMachine := range s.AWS.SAM.StateMachines {
			if stateMachine.IsUnmanaged() {
				continue
			}

			if stateMachine.LoggingConfiguration.LoggingEnabled.IsFalse() {
				results.Add(
					"Logging is not enabled,",
					stateMachine.LoggingConfiguration.LoggingEnabled,
				)
			} else {
				results.AddPassed(&stateMachine)
			}
		}
		return
	},
)
