package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoDefaultVpc = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0101",
		Aliases:     []string{"aws-vpc-no-default-vpc"},
		Provider:    providers2.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-default-vpc",
		Summary:     "AWS best practice to not use the default VPC for workflows",
		Impact:      "The default VPC does not have critical security features applied",
		Resolution:  "Create a non-default vpc for resources to be created in",
		Explanation: `Default VPC does not have a lot of the critical security features that standard VPC comes with, new resources should not be created in the default VPC and it should not be present in the Terraform.`,
		Links: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoDefaultVpcGoodExamples,
			BadExamples:         terraformNoDefaultVpcBadExamples,
			Links:               terraformNoDefaultVpcLinks,
			RemediationMarkdown: terraformNoDefaultVpcRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, def := range s.AWS.EC2.DefaultVPCs {
			results.Add(
				"Default VPC is used.",
				&def,
			)
		}
		return
	},
)
