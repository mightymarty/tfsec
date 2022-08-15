package cloudwatch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	cloudwatch2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudwatch"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var requireNonMFALoginAlarm = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0148",
		Provider:   providers2.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-non-mfa-login-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA",
		Impact:     "Not alerting on logins with no MFA allows the risk to go un-notified.",
		Resolution: "Create an alarm to alert on non MFA logins",
		Frameworks: map[framework2.Framework][]string{
			framework2.CIS_AWS_1_2: {
				"3.2",
			},
			framework2.CIS_AWS_1_4: {
				"4.2",
			},
		},
		Explanation: `YYou can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms.   
                                                                              
  CIS recommends that you create a metric filter and alarm console logins that  aren't protected by MFA. Monitoring for single-factor console logins increases visibility into accounts that aren't protected by MFA.`,
		Links: []string{
			"https://aws.amazon.com/iam/features/mfa/",
		},
		Terraform:      &scan2.EngineMetadata{},
		CloudFormation: &scan2.EngineMetadata{},
		Severity:       severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {

		multiRegionTrails := s.AWS.CloudTrail.MultiRegionTrails()
		for _, trail := range multiRegionTrails {
			logGroup := s.AWS.CloudWatch.GetLogGroupByArn(trail.CloudWatchLogsLogGroupArn.Value())
			if logGroup == nil || trail.IsLogging.IsFalse() {
				continue
			}

			var metricFilter cloudwatch2.MetricFilter
			var found bool
			for _, filter := range logGroup.MetricFilters {
				if filter.FilterPattern.Contains(`($.eventName = "ConsoleLogin") && 
($.additionalEventData.MFAUsed != "Yes") && 
($.userIdentity.type=="IAMUser") && 
($.responseElements.ConsoleLogin == "Success")`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no non-MFA login log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no non-MFA login alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
