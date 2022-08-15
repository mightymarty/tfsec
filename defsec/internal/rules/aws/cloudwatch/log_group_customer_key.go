package cloudwatch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckLogGroupCustomerKey = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0017",
		Provider:    providers2.AWSProvider,
		Service:     "cloudwatch",
		ShortCode:   "log-group-customer-key",
		Summary:     "CloudWatch log groups should be encrypted using CMK",
		Impact:      "Log data may be leaked if the logs are compromised. No auditing of who have viewed the logs.",
		Resolution:  "Enable CMK encryption of CloudWatch Log Groups",
		Explanation: `CloudWatch log groups are encrypted by default, however, to get the full benefit of controlling key rotation and other KMS aspects a KMS CMK should be used.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformLogGroupCustomerKeyGoodExamples,
			BadExamples:         terraformLogGroupCustomerKeyBadExamples,
			Links:               terraformLogGroupCustomerKeyLinks,
			RemediationMarkdown: terraformLogGroupCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationLogGroupCustomerKeyGoodExamples,
			BadExamples:         cloudFormationLogGroupCustomerKeyBadExamples,
			Links:               cloudFormationLogGroupCustomerKeyLinks,
			RemediationMarkdown: cloudFormationLogGroupCustomerKeyRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, group := range s.AWS.CloudWatch.LogGroups {
			if group.KMSKeyID.IsEmpty() {
				results.Add(
					"Log group is not encrypted.",
					group.KMSKeyID,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
