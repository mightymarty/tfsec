package elasticsearch

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0043",
		Provider:    providers2.AWSProvider,
		Service:     "elastic-search",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Elasticsearch domain uses plaintext traffic for node to node communication.",
		Impact:      "In transit data between nodes could be read if intercepted",
		Resolution:  "Enable encrypted node to node communication",
		Explanation: `Traffic flowing between Elasticsearch nodes should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/ntn.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, domain := range s.AWS.Elasticsearch.Domains {
			if domain.TransitEncryption.Enabled.IsFalse() {
				results.Add(
					"Domain does not have in-transit encryption enabled.",
					domain.TransitEncryption.Enabled,
				)
			} else {
				results.AddPassed(&domain)
			}
		}
		return
	},
)
