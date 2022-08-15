package cloudtrail

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	framework2 "github.com/mightymarty/tfsec/defsec/pkg/framework"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableAllRegions = rules.Register(
	scan2.Rule{
		AVDID:     "AVD-AWS-0014",
		Provider:  providers2.AWSProvider,
		Service:   "cloudtrail",
		ShortCode: "enable-all-regions",
		Frameworks: map[framework2.Framework][]string{
			framework2.Default:     nil,
			framework2.CIS_AWS_1_2: {"2.5"},
		},
		Summary:     "Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed",
		Impact:      "Activity could be happening in your account in a different region",
		Resolution:  "Enable Cloudtrail in all regions",
		Explanation: `When creating Cloudtrail in the AWS Management Console the trail is configured by default to be multi-region, this isn't the case with the Terraform resource. Cloudtrail should cover the full AWS account to ensure you can track changes in regions you are not actively operting in.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableAllRegionsGoodExamples,
			BadExamples:         terraformEnableAllRegionsBadExamples,
			Links:               terraformEnableAllRegionsLinks,
			RemediationMarkdown: terraformEnableAllRegionsRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableAllRegionsGoodExamples,
			BadExamples:         cloudFormationEnableAllRegionsBadExamples,
			Links:               cloudFormationEnableAllRegionsLinks,
			RemediationMarkdown: cloudFormationEnableAllRegionsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.IsMultiRegion.IsFalse() {
				results.Add(
					"Trail is not enabled across all regions.",
					trail.IsMultiRegion,
				)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)
