package ec2

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckIMDSAccessRequiresToken = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0028",
		Provider:   providers2.AWSProvider,
		Service:    "ec2",
		ShortCode:  "enforce-http-token-imds",
		Summary:    "aws_instance should activate session tokens for Instance Metadata Service.",
		Impact:     "Instance metadata service can be interacted with freely",
		Resolution: "Enable HTTP token requirement for IMDS",
		Explanation: `
IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
`,

		Links: []string{
			"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
		},

		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforceHttpTokenImdsGoodExamples,
			BadExamples:         terraformEnforceHttpTokenImdsBadExamples,
			Links:               terraformEnforceHttpTokenImdsLinks,
			RemediationMarkdown: terraformEnforceHttpTokenImdsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, instance := range s.AWS.EC2.Instances {
			if !instance.RequiresIMDSToken() && !instance.HasHTTPEndpointDisabled() {
				results.Add(
					"Instance does not require IMDS access to require a token",
					instance.MetadataOptions.HttpTokens,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return results
	},
)
