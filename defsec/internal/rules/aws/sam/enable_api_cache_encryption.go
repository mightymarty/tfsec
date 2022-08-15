package sam

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableApiCacheEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0110",
		Provider:    providers2.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-api-cache-encryption",
		Summary:     "SAM API must have data cache enabled",
		Impact:      "Data stored in the cache that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable cache encryption",
		Explanation: `Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-methodsetting.html#cfn-apigateway-stage-methodsetting-cachedataencrypted",
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableApiCacheEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableApiCacheEncryptionBadExamples,
			Links:               cloudFormationEnableApiCacheEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableApiCacheEncryptionRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.IsUnmanaged() {
				continue
			}

			if api.RESTMethodSettings.CacheDataEncrypted.IsFalse() {
				results.Add(
					"Cache data is not encrypted.",
					api.RESTMethodSettings.CacheDataEncrypted,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
