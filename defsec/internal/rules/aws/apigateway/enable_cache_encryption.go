package apigateway

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableCacheEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0002",
		Provider:    providers2.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-cache-encryption",
		Summary:     "API Gateway must have cache enabled",
		Impact:      "Data stored in the cache that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable cache encryption",
		Explanation: `Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableCacheEncryptionGoodExamples,
			BadExamples:         terraformEnableCacheEncryptionBadExamples,
			Links:               terraformEnableCacheEncryptionLinks,
			RemediationMarkdown: terraformEnableCacheEncryptionRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.IsUnmanaged() {
				continue
			}
			for _, stage := range api.Stages {
				if stage.IsUnmanaged() {
					continue
				}
				for _, settings := range stage.RESTMethodSettings {
					if settings.IsUnmanaged() {
						continue
					}
					if settings.CacheEnabled.IsFalse() {
						continue
					}
					if settings.CacheDataEncrypted.IsFalse() {
						results.Add(
							"Cache data is not encrypted.",
							settings.CacheDataEncrypted,
						)
					} else {
						results.AddPassed(&settings)
					}
				}
			}
		}
		return
	},
)
