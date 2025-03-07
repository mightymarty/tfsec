package apigateway

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	v12 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v1"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptAPIResourcesV1(modules terraform2.Modules, apiBlock *terraform2.Block) []v12.Resource {
	var resources []v12.Resource
	for _, resourceBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_resource", "rest_api_id") {
		method := v12.Resource{
			Metadata: resourceBlock.GetMetadata(),
			Methods:  adaptAPIMethodsV1(modules, resourceBlock),
		}
		resources = append(resources, method)
	}
	return resources
}

func adaptAPIMethodsV1(modules terraform2.Modules, resourceBlock *terraform2.Block) []v12.Method {
	var methods []v12.Method
	for _, methodBlock := range modules.GetReferencingResources(resourceBlock, "aws_api_gateway_method", "resource_id") {
		method := v12.Method{
			Metadata:          methodBlock.GetMetadata(),
			HTTPMethod:        methodBlock.GetAttribute("http_method").AsStringValueOrDefault("", methodBlock),
			AuthorizationType: methodBlock.GetAttribute("authorization").AsStringValueOrDefault("", methodBlock),
			APIKeyRequired:    methodBlock.GetAttribute("api_key_required").AsBoolValueOrDefault(false, methodBlock),
		}
		methods = append(methods, method)
	}
	return methods
}

func adaptAPIsV1(modules terraform2.Modules) []v12.API {

	var apis []v12.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_api_gateway_stage")

	for _, apiBlock := range modules.GetResourcesByType("aws_api_gateway_rest_api") {
		api := v12.API{
			Metadata:  apiBlock.GetMetadata(),
			Name:      apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock),
			Stages:    nil,
			Resources: adaptAPIResourcesV1(modules, apiBlock),
		}

		for _, stageBlock := range modules.GetReferencingResources(apiBlock, "aws_api_gateway_stage", "rest_api_id") {
			apiStageIDs.Resolve(stageBlock.ID())
			stage := adaptStageV1(stageBlock, modules)

			api.Stages = append(api.Stages, stage)
		}

		apis = append(apis, api)
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := v12.API{
			Metadata: types2.NewUnmanagedMetadata(),
			Name:     types2.StringDefault("", types2.NewUnmanagedMetadata()),
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV1(stage, modules))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV1(stageBlock *terraform2.Block, modules terraform2.Modules) v12.Stage {
	stage := v12.Stage{
		Metadata: stageBlock.GetMetadata(),
		Name:     stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock),
		AccessLogging: v12.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: types2.StringDefault("", stageBlock.GetMetadata()),
		},
		XRayTracingEnabled: stageBlock.GetAttribute("xray_tracing_enabled").AsBoolValueOrDefault(false, stageBlock),
	}
	for _, methodSettings := range modules.GetReferencingResources(stageBlock, "aws_api_gateway_method_settings", "stage_name") {

		restMethodSettings := v12.RESTMethodSettings{
			Metadata:           methodSettings.GetMetadata(),
			Method:             types2.String("", methodSettings.GetMetadata()),
			CacheDataEncrypted: types2.BoolDefault(false, methodSettings.GetMetadata()),
			CacheEnabled:       types2.BoolDefault(false, methodSettings.GetMetadata()),
		}

		if settings := methodSettings.GetBlock("settings"); settings.IsNotNil() {
			if encrypted := settings.GetAttribute("cache_data_encrypted"); encrypted.IsNotNil() {
				restMethodSettings.CacheDataEncrypted = settings.GetAttribute("cache_data_encrypted").AsBoolValueOrDefault(false, settings)
			}
			if encrypted := settings.GetAttribute("caching_enabled"); encrypted.IsNotNil() {
				restMethodSettings.CacheEnabled = settings.GetAttribute("caching_enabled").AsBoolValueOrDefault(false, settings)
			}
		}

		stage.RESTMethodSettings = append(stage.RESTMethodSettings, restMethodSettings)
	}

	stage.Name = stageBlock.GetAttribute("stage_name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = types2.StringDefault("", stageBlock.GetMetadata())
	}

	return stage
}
