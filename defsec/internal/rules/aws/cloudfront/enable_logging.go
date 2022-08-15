package cloudfront

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableLogging = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0010",
		Provider:    providers2.AWSProvider,
		Service:     "cloudfront",
		ShortCode:   "enable-logging",
		Summary:     "Cloudfront distribution should have Access Logging configured",
		Impact:      "Logging provides vital information about access and usage",
		Resolution:  "Enable logging for CloudFront distributions",
		Explanation: `You should configure CloudFront Access Logging to create log files that contain detailed information about every user request that CloudFront receives`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableLoggingGoodExamples,
			BadExamples:         terraformEnableLoggingBadExamples,
			Links:               terraformEnableLoggingLinks,
			RemediationMarkdown: terraformEnableLoggingRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableLoggingGoodExamples,
			BadExamples:         cloudFormationEnableLoggingBadExamples,
			Links:               cloudFormationEnableLoggingLinks,
			RemediationMarkdown: cloudFormationEnableLoggingRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, dist := range s.AWS.Cloudfront.Distributions {
			if dist.Logging.Bucket.IsEmpty() {
				results.Add(
					"Distribution does not have logging enabled.",
					dist.Logging.Bucket,
				)
			} else {
				results.AddPassed(&dist)
			}
		}
		return
	},
)
