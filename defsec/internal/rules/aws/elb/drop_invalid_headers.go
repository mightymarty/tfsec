package elb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	elb2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elb"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckDropInvalidHeaders = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-AWS-0052",
		Provider:   providers2.AWSProvider,
		Service:    "elb",
		ShortCode:  "drop-invalid-headers",
		Summary:    "Load balancers should drop invalid headers",
		Impact:     "Invalid headers being passed through to the target of the load balance may exploit vulnerabilities",
		Resolution: "Set drop_invalid_header_fields to true",
		Explanation: `Passing unknown or invalid headers through to the target poses a potential risk of compromise. 

By setting drop_invalid_header_fields to true, anything that doe not conform to well known, defined headers will be removed by the load balancer.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformDropInvalidHeadersGoodExamples,
			BadExamples:         terraformDropInvalidHeadersBadExamples,
			Links:               terraformDropInvalidHeadersLinks,
			RemediationMarkdown: terraformDropInvalidHeadersRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			if lb.IsUnmanaged() || !lb.Type.EqualTo(elb2.TypeApplication) || lb.IsUnmanaged() {
				continue
			}
			if lb.DropInvalidHeaderFields.IsFalse() {
				results.Add(
					"Application load balancer is not set to drop invalid headers.",
					lb.DropInvalidHeaderFields,
				)
			} else {
				results.AddPassed(&lb)
			}
		}
		return
	},
)
