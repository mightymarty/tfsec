package mq

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableGeneralLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0071",
		Provider:    providers2.AWSProvider,
		Service:     "mq",
		ShortCode:   "enable-general-logging",
		Summary:     "MQ Broker should have general logging enabled",
		Impact:      "Without logging it is difficult to trace issues",
		Resolution:  "Enable general logging",
		Explanation: `Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableGeneralLoggingGoodExamples,
			BadExamples:         terraformEnableGeneralLoggingBadExamples,
			Links:               terraformEnableGeneralLoggingLinks,
			RemediationMarkdown: terraformEnableGeneralLoggingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableGeneralLoggingGoodExamples,
			BadExamples:         cloudFormationEnableGeneralLoggingBadExamples,
			Links:               cloudFormationEnableGeneralLoggingLinks,
			RemediationMarkdown: cloudFormationEnableGeneralLoggingRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.Logging.General.IsFalse() {
				results.Add(
					"Broker does not have general logging enabled.",
					broker.Logging.General,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)
