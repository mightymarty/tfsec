package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/cidr"
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNoPublicControlPlane = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0053",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "no-public-control-plane",
		Summary:     "GKE Control Plane should not be publicly accessible",
		Impact:      "GKE control plane exposed to public internet",
		Resolution:  "Use private nodes and master authorised networks to prevent exposure",
		Explanation: `The GKE control plane is exposed to the public internet by default.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNoPublicControlPlaneGoodExamples,
			BadExamples:         terraformNoPublicControlPlaneBadExamples,
			Links:               terraformNoPublicControlPlaneLinks,
			RemediationMarkdown: terraformNoPublicControlPlaneRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			for _, block := range cluster.MasterAuthorizedNetworks.CIDRs {
				if cidr.IsPublic(block.Value()) {
					results.Add(
						"Cluster exposes control plane to the public internet.",
						block,
					)
				} else {
					results.AddPassed(&cluster)
				}

			}
		}
		return
	},
)
