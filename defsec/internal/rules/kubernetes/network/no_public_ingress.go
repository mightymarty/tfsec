package network

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicIngress = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-KUBE-0001",
		Provider:    providers2.KubernetesProvider,
		Service:     "network",
		ShortCode:   "no-public-ingress",
		Summary:     "Public ingress should not be allowed via network policies",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Remove public access except where explicitly required",
		Explanation: `You should not expose infrastructure to the public internet except where explicitly required`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, policy := range s.Kubernetes.NetworkPolicies {
			if policy.IsUnmanaged() {
				continue
			}
			for _, source := range policy.Spec.Ingress.SourceCIDRs {
				if cidr.IsPublic(source.Value()) {
					results.Add(
						"Network policy allows ingress from the public internet.",
						source,
					)
				} else {
					results.AddPassed(source)
				}
			}
		}
		return
	},
)
