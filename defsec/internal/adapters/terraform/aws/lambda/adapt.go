package lambda

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	lambda2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/lambda"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) lambda2.Lambda {

	adapter := adapter{
		permissionIDs: modules.GetChildResourceIDMapByType("aws_lambda_permission"),
	}

	return lambda2.Lambda{
		Functions: adapter.adaptFunctions(modules),
	}
}

type adapter struct {
	permissionIDs terraform2.ResourceIDResolutions
}

func (a *adapter) adaptFunctions(modules terraform2.Modules) []lambda2.Function {

	var functions []lambda2.Function
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_lambda_function") {
			functions = append(functions, a.adaptFunction(resource, modules, a.permissionIDs))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.permissionIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := lambda2.Function{
			Metadata: types2.NewUnmanagedMetadata(),
			Tracing: lambda2.Tracing{
				Metadata: types2.NewUnmanagedMetadata(),
				Mode:     types2.StringDefault("", types2.NewUnmanagedMetadata()),
			},
			Permissions: nil,
		}
		for _, permission := range orphanResources {
			orphanage.Permissions = append(orphanage.Permissions, a.adaptPermission(permission))
		}
		functions = append(functions, orphanage)
	}

	return functions
}

func (a *adapter) adaptFunction(function *terraform2.Block, modules terraform2.Modules, orphans terraform2.ResourceIDResolutions) lambda2.Function {
	var permissions []lambda2.Permission
	for _, module := range modules {
		for _, p := range module.GetResourcesByType("aws_lambda_permission") {
			if referencedBlock, err := module.GetReferencedBlock(p.GetAttribute("function_name"), p); err == nil && referencedBlock == function {
				permissions = append(permissions, a.adaptPermission(p))
				delete(orphans, p.ID())
			}
		}
	}

	return lambda2.Function{
		Metadata:    function.GetMetadata(),
		Tracing:     a.adaptTracing(function),
		Permissions: permissions,
	}
}

func (a *adapter) adaptTracing(function *terraform2.Block) lambda2.Tracing {
	if tracingConfig := function.GetBlock("tracing_config"); tracingConfig.IsNotNil() {
		return lambda2.Tracing{
			Metadata: tracingConfig.GetMetadata(),
			Mode:     tracingConfig.GetAttribute("mode").AsStringValueOrDefault("", tracingConfig),
		}
	}

	return lambda2.Tracing{
		Metadata: function.GetMetadata(),
		Mode:     types2.StringDefault("", function.GetMetadata()),
	}
}

func (a *adapter) adaptPermission(permission *terraform2.Block) lambda2.Permission {
	sourceARNAttr := permission.GetAttribute("source_arn")
	sourceARN := sourceARNAttr.AsStringValueOrDefault("", permission)

	if len(sourceARNAttr.AllReferences()) > 0 {
		sourceARN = types2.String(sourceARNAttr.AllReferences()[0].NameLabel(), sourceARNAttr.GetMetadata())
	}

	return lambda2.Permission{
		Metadata:  permission.GetMetadata(),
		Principal: permission.GetAttribute("principal").AsStringValueOrDefault("", permission),
		SourceARN: sourceARN,
	}
}
