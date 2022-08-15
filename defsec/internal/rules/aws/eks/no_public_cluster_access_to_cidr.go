package eks

import (
	"fmt"
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicClusterAccessToCidr = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0041",
		Provider:    providers2.AWSProvider,
		Service:     "eks",
		ShortCode:   "no-public-cluster-access-to-cidr",
		Summary:     "EKS cluster should not have open CIDR range for public access",
		Impact:      "EKS can be accessed from the internet",
		Resolution:  "Don't enable public access to EKS Clusters",
		Explanation: `EKS Clusters have public access cidrs set to 0.0.0.0/0 by default which is wide open to the internet. This should be explicitly set to a more specific private CIDR range`,
		Links: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/create-public-private-vpc.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicClusterAccessToCidrGoodExamples,
			BadExamples:         terraformNoPublicClusterAccessToCidrBadExamples,
			Links:               terraformNoPublicClusterAccessToCidrLinks,
			RemediationMarkdown: terraformNoPublicClusterAccessToCidrRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.PublicAccessEnabled.IsFalse() {
				continue
			}
			for _, accessCidr := range cluster.PublicAccessCIDRs {
				if cidr.IsPublic(accessCidr.Value()) {
					results.Add(
						fmt.Sprintf("Cluster allows access from a public CIDR: %s.", accessCidr.Value()),
						accessCidr,
					)
				} else {
					results.AddPassed(&cluster)
				}
			}
		}
		return
	},
)
