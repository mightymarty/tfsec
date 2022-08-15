package redshift

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUsesVPC = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0127",
		Provider:   providers2.AWSProvider,
		Service:    "redshift",
		ShortCode:  "use-vpc",
		Summary:    "Redshift cluster should be deployed into a specific VPC",
		Impact:     "Redshift cluster does not benefit from VPC security if it is deployed in EC2 classic mode",
		Resolution: "Deploy Redshift cluster into a non default VPC",
		Explanation: `Redshift clusters that are created without subnet details will be created in EC2 classic mode, meaning that they will be outside of a known VPC and running in tennant.

In order to benefit from the additional security features achieved with using an owned VPC, the subnet should be set.`,
		Links: []string{
			"https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseVpcGoodExamples,
			BadExamples:         terraformUseVpcBadExamples,
			Links:               terraformUseVpcLinks,
			RemediationMarkdown: terraformUseVpcRemediationMarkdown,
		},
		CloudFormation: &scan2.EngineMetadata{
			GoodExamples:        cloudFormationUseVpcGoodExamples,
			BadExamples:         cloudFormationUseVpcBadExamples,
			Links:               cloudFormationUseVpcLinks,
			RemediationMarkdown: cloudFormationUseVpcRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.AWS.Redshift.Clusters {
			if cluster.SubnetGroupName.IsEmpty() {
				results.Add(
					"Cluster is deployed outside of a VPC.",
					cluster.SubnetGroupName,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
