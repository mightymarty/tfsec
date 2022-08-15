package elb

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var outdatedSSLPolicies = []string{
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-TLS-1-0-2015-04",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
}

var CheckUseSecureTlsPolicy = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AWS-0047",
		Provider:    providers2.AWSProvider,
		Service:     "elb",
		ShortCode:   "use-secure-tls-policy",
		Summary:     "An outdated SSL policy is in use by a load balancer.",
		Impact:      "The SSL policy is outdated and has known vulnerabilities",
		Resolution:  "Use a more recent TLS/SSL policy for the load balancer",
		Explanation: `You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseSecureTlsPolicyGoodExamples,
			BadExamples:         terraformUseSecureTlsPolicyBadExamples,
			Links:               terraformUseSecureTlsPolicyLinks,
			RemediationMarkdown: terraformUseSecureTlsPolicyRemediationMarkdown,
		},
		Severity: severity2.Critical,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			for _, listener := range lb.Listeners {
				for _, outdated := range outdatedSSLPolicies {
					if listener.TLSPolicy.EqualTo(outdated) {
						results.Add(
							"Listener uses an outdated TLS policy.",
							listener.TLSPolicy,
						)
					} else {
						results.AddPassed(&listener)
					}
				}
			}
		}
		return
	},
)
