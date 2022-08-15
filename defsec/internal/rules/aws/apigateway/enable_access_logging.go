package apigateway

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAccessLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0001",
		Provider:    providers2.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-access-logging",
		Summary:     "API Gateway stages for V1 and V2 should have access logging enabled",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for API Gateway stages",
		Explanation: `API Gateway stages should have access log settings block configured to track all access to a particular stage. This should be applied to both v1 and v2 gateway stages.`,
		Links: []string{
			"https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAccessLoggingGoodExamples,
			BadExamples:         terraformEnableAccessLoggingBadExamples,
			Links:               terraformEnableAccessLoggingLinks,
			RemediationMarkdown: terraformEnableAccessLoggingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableAccessLoggingGoodExamples,
			BadExamples:         cloudFormationEnableAccessLoggingBadExamples,
			Links:               cloudFormationEnableAccessLoggingLinks,
			RemediationMarkdown: cloudFormationEnableAccessLoggingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			for _, stage := range api.Stages {
				if stage.IsUnmanaged() {
					continue
				}
				if stage.AccessLogging.CloudwatchLogGroupARN.IsEmpty() {
					results.Add(
						"Access logging is not configured.",
						stage.AccessLogging.CloudwatchLogGroupARN,
					)
				} else {
					results.AddPassed(&api)
				}
			}
		}
		for _, api := range s.AWS.APIGateway.V2.APIs {
			for _, stage := range api.Stages {
				if stage.IsUnmanaged() {
					continue
				}
				if stage.AccessLogging.CloudwatchLogGroupARN.IsEmpty() {
					results.Add(
						"Access logging is not configured.",
						stage.AccessLogging.CloudwatchLogGroupARN,
					)
				} else {
					results.AddPassed(&api)
				}
			}
		}
		return
	},
)
