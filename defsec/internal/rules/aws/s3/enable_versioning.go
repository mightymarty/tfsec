package s3

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckVersioningIsEnabled = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0090",
		Provider:   providers2.AWSProvider,
		Service:    "s3",
		ShortCode:  "enable-versioning",
		Summary:    "S3 Data should be versioned",
		Impact:     "Deleted or modified data would not be recoverable",
		Resolution: "Enable versioning to protect against accidental/malicious removal or modification",
		Explanation: `
Versioning in Amazon S3 is a means of keeping multiple variants of an object in the same bucket. 
You can use the S3 Versioning feature to preserve, retrieve, and restore every version of every object stored in your buckets. 
With versioning you can recover more easily from both unintended user actions and application failures.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableVersioningGoodExamples,
			BadExamples:         terraformEnableVersioningBadExamples,
			Links:               terraformEnableVersioningLinks,
			RemediationMarkdown: terraformEnableVersioningRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableVersioningGoodExamples,
			BadExamples:         cloudFormationEnableVersioningBadExamples,
			Links:               cloudFormationEnableVersioningLinks,
			RemediationMarkdown: cloudFormationEnableVersioningRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if !bucket.Versioning.Enabled.IsTrue() {
				results.Add(
					"Bucket does not have versioning enabled",
					bucket.Versioning.Enabled,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
