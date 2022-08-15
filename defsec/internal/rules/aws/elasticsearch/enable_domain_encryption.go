package elasticsearch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableDomainEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0048",
		Provider:    providers2.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-domain-encryption",
		Summary:     "Elasticsearch domain isn't encrypted at rest.",
		Impact:      "Data will be readable if compromised",
		Resolution:  "Enable ElasticSearch domain encryption",
		Explanation: `You should ensure your Elasticsearch data is encrypted at rest to help prevent sensitive information from being read by unauthorised users.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableDomainEncryptionGoodExamples,
			BadExamples:         terraformEnableDomainEncryptionBadExamples,
			Links:               terraformEnableDomainEncryptionLinks,
			RemediationMarkdown: terraformEnableDomainEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableDomainEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableDomainEncryptionBadExamples,
			Links:               cloudFormationEnableDomainEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableDomainEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.AtRestEncryption.Enabled.IsFalse() {
				results.Add(
					"Domain does not have at-rest encryption enabled.",
					domain.AtRestEncryption.Enabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
