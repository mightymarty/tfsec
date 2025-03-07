package mq

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAuditLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0070",
		Provider:    providers2.AWSProvider,
		Service:     "mq",
		ShortCode:   "enable-audit-logging",
		Summary:     "MQ Broker should have audit logging enabled",
		Impact:      "Without audit logging it is difficult to trace activity in the MQ broker",
		Resolution:  "Enable audit logging",
		Explanation: `Logging should be enabled to allow tracing of issues and activity to be investigated more fully. Logs provide additional information and context which is often invalauble during investigation`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/configure-logging-monitoring-activemq.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAuditLoggingGoodExamples,
			BadExamples:         terraformEnableAuditLoggingBadExamples,
			Links:               terraformEnableAuditLoggingLinks,
			RemediationMarkdown: terraformEnableAuditLoggingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableAuditLoggingGoodExamples,
			BadExamples:         cloudFormationEnableAuditLoggingBadExamples,
			Links:               cloudFormationEnableAuditLoggingLinks,
			RemediationMarkdown: cloudFormationEnableAuditLoggingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.Logging.Audit.IsFalse() {
				results.Add(
					"Broker does not have audit logging enabled.",
					broker.Logging.Audit,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)
