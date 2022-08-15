package authorization

import (
	"github.com/mightymarty/tfsec/defsec/internal/rules"
	providers2 "github.com/mightymarty/tfsec/defsec/pkg/providers"
	scan2 "github.com/mightymarty/tfsec/defsec/pkg/scan"
	severity2 "github.com/mightymarty/tfsec/defsec/pkg/severity"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
)

var CheckLimitRoleActions = rules.Register(
	scan2.Rule{
		AVDID:       "AVD-AZU-0030",
		Provider:    providers2.AzureProvider,
		Service:     "authorization",
		ShortCode:   "limit-role-actions",
		Summary:     "Roles limited to the required actions",
		Impact:      "Open permissions for subscriptions could result in an easily compromisable account",
		Resolution:  "Use targeted permissions for roles",
		Explanation: `The permissions granted to a role should be kept to the minimum required to be able to do the task. Wildcard permissions must not be used.`,
		Links:       []string{},
		Terraform: &scan2.EngineMetadata{
			GoodExamples:        terraformLimitRoleActionsGoodExamples,
			BadExamples:         terraformLimitRoleActionsBadExamples,
			Links:               terraformLimitRoleActionsLinks,
			RemediationMarkdown: terraformLimitRoleActionsRemediationMarkdown,
		},
		Severity: severity2.Medium,
	},
	func(s *state2.State) (results scan2.Results) {
		for _, roleDef := range s.Azure.Authorization.RoleDefinitions {
			for _, perm := range roleDef.Permissions {
				for _, action := range perm.Actions {
					if action.Contains("*") {
						for _, scope := range roleDef.AssignableScopes {
							if scope.EqualTo("/") {
								results.Add(
									"Role definition uses wildcard action with all scopes.",
									action,
								)
							} else {
								results.AddPassed(&perm)
							}
						}

					}
				}
			}
		}
		return
	},
)
