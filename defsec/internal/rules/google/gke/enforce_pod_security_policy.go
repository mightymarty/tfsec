package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckEnforcePodSecurityPolicy = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-GCP-0047",
		Provider:   providers2.GoogleProvider,
		Service:    "gke",
		ShortCode:  "enforce-pod-security-policy",
		Summary:    "Pod security policy enforcement not defined.",
		Impact:     "Pods could be operating with more permissions than required to be effective",
		Resolution: "Use security policies for pods to restrict permissions to those needed to be effective",
		Explanation: `By default, Pods in Kubernetes can operate with capabilities beyond what they require. You should constrain the Pod's capabilities to only those required for that workload.

Kubernetes offers controls for restricting your Pods to execute with only explicitly granted capabilities. 

Pod Security Policy allows you to set smart defaults for your Pods, and enforce controls you want to enable across your fleet. 

The policies you define should be specific to the needs of your application`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#admission_controllers",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformEnforcePodSecurityPolicyGoodExamples,
			BadExamples:         terraformEnforcePodSecurityPolicyBadExamples,
			Links:               terraformEnforcePodSecurityPolicyLinks,
			RemediationMarkdown: terraformEnforcePodSecurityPolicyRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.PodSecurityPolicy.Enabled.IsFalse() {
				results.Add(
					"Cluster pod security policy is not enforced.",
					cluster.PodSecurityPolicy.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
