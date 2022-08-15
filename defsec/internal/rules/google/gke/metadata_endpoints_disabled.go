package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckMetadataEndpointsDisabled = rules.Register(
	scan2.Rule{
		AVDID:      "AVD-GCP-0048",
		Provider:   providers2.GoogleProvider,
		Service:    "gke",
		ShortCode:  "metadata-endpoints-disabled",
		Summary:    "Legacy metadata endpoints enabled.",
		Impact:     "Legacy metadata endpoints don't require metadata headers",
		Resolution: "Disable legacy metadata endpoints",
		Explanation: `The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. 

This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. 

Unless specifically required, we recommend you disable these legacy APIs.

When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformMetadataEndpointsDisabledGoodExamples,
			BadExamples:         terraformMetadataEndpointsDisabledBadExamples,
			Links:               terraformMetadataEndpointsDisabledLinks,
			RemediationMarkdown: terraformMetadataEndpointsDisabledRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.RemoveDefaultNodePool.IsTrue() {
				for _, pool := range cluster.NodePools {
					if pool.NodeConfig.EnableLegacyEndpoints.IsTrue() {
						results.Add(
							"Cluster has legacy metadata endpoints enabled.",
							pool.NodeConfig.EnableLegacyEndpoints,
						)
					}
				}
			} else if cluster.NodeConfig.EnableLegacyEndpoints.IsTrue() {
				results.Add(
					"Cluster has legacy metadata endpoints enabled.",
					cluster.NodeConfig.EnableLegacyEndpoints,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
