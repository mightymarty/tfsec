package gke

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckNodePoolUsesCos = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-GCP-0054",
		Provider:    providers2.GoogleProvider,
		Service:     "gke",
		ShortCode:   "node-pool-uses-cos",
		Summary:     "Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image",
		Impact:      "COS is the recommended OS image to use on cluster nodes",
		Resolution:  "Use the COS image type",
		Explanation: `GKE supports several OS image types but COS is the recommended OS image to use on cluster nodes for enhanced security`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformNodePoolUsesCosGoodExamples,
			BadExamples:         terraformNodePoolUsesCosBadExamples,
			Links:               terraformNodePoolUsesCosLinks,
			RemediationMarkdown: terraformNodePoolUsesCosRemediationMarkdown,
		},
		Severity: severity2.Low,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.IsManaged() {
				if cluster.NodeConfig.ImageType.NotEqualTo("") && cluster.NodeConfig.ImageType.NotEqualTo("COS_CONTAINERD", types.IgnoreCase) && cluster.NodeConfig.ImageType.NotEqualTo("COS", types.IgnoreCase) {
					results.Add(
						"Cluster is not configuring node pools to use the COS containerd image type by default.",
						cluster.NodeConfig.ImageType,
					)
				} else {
					results.AddPassed(&cluster)
				}
			}
			for _, pool := range cluster.NodePools {
				if pool.NodeConfig.ImageType.NotEqualTo("COS_CONTAINERD", types.IgnoreCase) && pool.NodeConfig.ImageType.NotEqualTo("COS", types.IgnoreCase) {
					results.Add(
						"Node pool is not using the COS containerd image type.",
						pool.NodeConfig.ImageType,
					)
				} else {
					results.AddPassed(&pool)
				}

			}
		}
		return
	},
)
