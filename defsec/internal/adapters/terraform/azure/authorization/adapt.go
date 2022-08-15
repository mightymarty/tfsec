package authorization

import (
	authorization2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/authorization"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) authorization2.Authorization {
	return authorization2.Authorization{
		RoleDefinitions: adaptRoleDefinitions(modules),
	}
}

func adaptRoleDefinitions(modules terraform2.Modules) []authorization2.RoleDefinition {
	var roleDefinitions []authorization2.RoleDefinition
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_role_definition") {
			roleDefinitions = append(roleDefinitions, adaptRoleDefinition(resource))
		}
	}
	return roleDefinitions
}

func adaptRoleDefinition(resource *terraform2.Block) authorization2.RoleDefinition {
	permissionsBlocks := resource.GetBlocks("permissions")
	var permissionsVal []authorization2.Permission

	for _, permissionsBlock := range permissionsBlocks {
		actionsAttr := permissionsBlock.GetAttribute("actions")
		permissionsVal = append(permissionsVal, authorization2.Permission{
			Metadata: permissionsBlock.GetMetadata(),
			Actions:  actionsAttr.AsStringValues(),
		})
	}

	assignableScopesAttr := resource.GetAttribute("assignable_scopes")
	return authorization2.RoleDefinition{
		Metadata:         resource.GetMetadata(),
		Permissions:      permissionsVal,
		AssignableScopes: assignableScopesAttr.AsStringValues(),
	}
}
