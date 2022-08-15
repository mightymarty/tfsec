package container

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckUseRbacPermissions = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0042",
		Provider:    providers2.AzureProvider,
		Service:     "container",
		ShortCode:   "use-rbac-permissions",
		Summary:     "Ensure RBAC is enabled on AKS clusters",
		Impact:      "No role based access control is in place for the AKS cluster",
		Resolution:  "Enable RBAC",
		Explanation: `Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
		},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformUseRbacPermissionsGoodExamples,
			BadExamples:         terraformUseRbacPermissionsBadExamples,
			Links:               terraformUseRbacPermissionsLinks,
			RemediationMarkdown: terraformUseRbacPermissionsRemediationMarkdown,
		},
		Severity: severity2.High,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.RoleBasedAccessControl.Enabled.IsFalse() {
				results.Add(
					"Cluster has RBAC disabled",
					cluster.RoleBasedAccessControl.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
