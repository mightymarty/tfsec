package ssm

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

var AvoidLeaksViaHTTP = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0134",
		Provider:    providers2.AWSProvider,
		Service:     "ssm",
		ShortCode:   "avoid-leaks-via-http",
		Summary:     "Secrets should not be exfiltrated using Terraform HTTP data blocks",
		Impact:      "Secrets could be exposed outside of the organisation.",
		Resolution:  "Remove this potential exfiltration HTTP request.",
		Explanation: `The data.http block can be used to send secret data outside of the organisation.`,
		Links: []string{
			"https://sprocketfox.io/xssfox/2022/02/09/terraformsupply/",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformAvoidLeaksViaHTTPGoodExamples,
			BadExamples:         terraformAvoidLeaksViaHTTPBadExamples,
			Links:               terraformAvoidLeaksViaHTTPLinks,
			RemediationMarkdown: terraformAvoidLeaksViaHTTPRemediationMarkdown,
		},
		CustomChecks: scan2.CustomChecks{
			Terraform: &scan2.TerraformCustomCheck{
				RequiredTypes:  []string{"data"},
				RequiredLabels: []string{"http"},
				Check: func(block *terraform2.Block, module *terraform2.Module) (results scan2.Results) {
					attr := block.GetAttribute("url")
					if attr.IsNil() {
						return
					}
					for _, ref := range attr.AllReferences() {
						if ref.BlockType().Name() == "resource" && ref.TypeLabel() == "aws_ssm_parameter" {
							results.Add("Potential exfiltration of secret value detected", block)
						}
					}
					return
				},
			},
		},
		Severity: severity2.Critical,
	},
	nil,
)
