package mq

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0072",
		Provider:    providers2.AWSProvider,
		Service:     "mq",
		ShortCode:   "no-public-access",
		Summary:     "Ensure MQ Broker is not publicly exposed",
		Impact:      "Publicly accessible MQ Broker may be vulnerable to compromise",
		Resolution:  "Disable public access when not required",
		Explanation: `Public access of the MQ broker should be disabled and only allow routes to applications that require access.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessBadExamples,
			Links:               cloudFormationNoPublicAccessLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.PublicAccess.IsTrue() {
				results.Add(
					"Broker has public access enabled.",
					broker.PublicAccess,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)
