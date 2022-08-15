package ecr

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableImageScans = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0030",
		Provider:    providers2.AWSProvider,
		Service:     "ecr",
		ShortCode:   "enable-image-scans",
		Summary:     "ECR repository has image scans disabled.",
		Impact:      "The ability to scan images is not being used and vulnerabilities will not be highlighted",
		Resolution:  "Enable ECR image scanning",
		Explanation: `Repository image scans should be enabled to ensure vulnerable software can be discovered and remediated as soon as possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableImageScansGoodExamples,
			BadExamples:         terraformEnableImageScansBadExamples,
			Links:               terraformEnableImageScansLinks,
			RemediationMarkdown: terraformEnableImageScansRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableImageScansGoodExamples,
			BadExamples:         cloudFormationEnableImageScansBadExamples,
			Links:               cloudFormationEnableImageScansLinks,
			RemediationMarkdown: cloudFormationEnableImageScansRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.ImageScanning.ScanOnPush.IsFalse() {
				results.Add(
					"Image scanning is not enabled.",
					repo.ImageScanning.ScanOnPush,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)
