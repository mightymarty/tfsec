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

var requireUnauthorizedApiCallAlarm = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0147",
		Provider:   providers2.AWSProvider,
		Service:    "cloudwatch",
		ShortCode:  "require-unauthorised-api-call-alarm",
		Summary:    "Ensure a log metric filter and alarm exist for unauthorized API calls",
		Impact:     "Unauthorized API Calls may be attempted without being notified. CloudTrail logs these actions but without the alarm you aren't actively notified.",
		Resolution: "Create an alarm to alert on unauthorized API calls",
		Frameworks: map[framework2.Framework][]string{
			framework2.CIS_AWS_1_2: {
				"3.1",
			},
			framework2.CIS_AWS_1_4: {
				"4.1",
			},
		},
		Explanation: `You can do real-time monitoring of API calls by directing CloudTrail logs to CloudWatch Logs and establishing corresponding metric filters and alarms. You can have more than one VPC in an account, and you can create a peer connection between two VPCs, enabling network traffic to route between VPCs.

CIS recommends that you create a metric filter and alarm for changes to VPCs. Monitoring these changes helps ensure that authentication and authorization controls remain intact.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html",
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
				if filter.FilterPattern.Contains(`($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`, types.IgnoreWhitespace) {
					metricFilter = filter
					found = true
					break
				}
			}

			if !found {
				results.Add("Cloudtrail has no unauthorized API log filter", trail)
				continue
			}

			if metricAlarm := s.AWS.CloudWatch.GetAlarmByMetricName(metricFilter.FilterName.Value()); metricAlarm == nil {
				results.Add("Cloudtrail has no unauthorized API alarm", trail)
				continue
			}

			results.AddPassed(trail)
		}

		return
	},
)
