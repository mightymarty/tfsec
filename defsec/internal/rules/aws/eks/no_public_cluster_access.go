package eks

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicClusterAccess = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0040",
		Provider:    providers2.AWSProvider,
		Service:     "eks",
		ShortCode:   "no-public-cluster-access",
		Summary:     "EKS Clusters should have the public access disabled",
		Impact:      "EKS can be access from the internet",
		Resolution:  "Don't enable public access to EKS Clusters",
		Explanation: `EKS clusters are available publicly by default, this should be explicitly disabled in the vpc_config of the EKS cluster resource.`,
		Links: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicClusterAccessGoodExamples,
			BadExamples:         terraformNoPublicClusterAccessBadExamples,
			Links:               terraformNoPublicClusterAccessLinks,
			RemediationMarkdown: terraformNoPublicClusterAccessRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.PublicAccessEnabled.IsTrue() {
				results.Add(
					"Public cluster access is enabled.",
					cluster.PublicAccessEnabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
