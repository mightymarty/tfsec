package apigateway

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	v22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptAPIsV2(modules terraform2.Modules) []v22.API {

	var apis []v22.API
	apiStageIDs := modules.GetChildResourceIDMapByType("aws_apigatewayv2_stage")

	for _, module := range modules {
		for _, apiBlock := range module.GetResourcesByType("aws_apigatewayv2_api") {
			api := v22.API{
				Metadata:     apiBlock.GetMetadata(),
				Name:         apiBlock.GetAttribute("name").AsStringValueOrDefault("", apiBlock),
				ProtocolType: apiBlock.GetAttribute("protocol_type").AsStringValueOrDefault("", apiBlock),
				Stages:       nil,
			}

			for _, stageBlock := range module.GetReferencingResources(apiBlock, "aws_apigatewayv2_stage", "api_id") {
				apiStageIDs.Resolve(stageBlock.ID())

				stage := adaptStageV2(stageBlock)

				api.Stages = append(api.Stages, stage)
			}

			apis = append(apis, api)
		}
	}

	orphanResources := modules.GetResourceByIDs(apiStageIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := v22.API{
			Metadata:     types2.NewUnmanagedMetadata(),
			Name:         types2.StringDefault("", types2.NewUnmanagedMetadata()),
			ProtocolType: types2.StringUnresolvable(types2.NewUnmanagedMetadata()),
			Stages:       nil,
		}
		for _, stage := range orphanResources {
			orphanage.Stages = append(orphanage.Stages, adaptStageV2(stage))
		}
		apis = append(apis, orphanage)
	}

	return apis
}

func adaptStageV2(stageBlock *terraform2.Block) v22.Stage {
	stage := v22.Stage{
		Metadata: stageBlock.GetMetadata(),
		AccessLogging: v22.AccessLogging{
			Metadata:              stageBlock.GetMetadata(),
			CloudwatchLogGroupARN: types2.StringDefault("", stageBlock.GetMetadata()),
		},
	}
	stage.Name = stageBlock.GetAttribute("name").AsStringValueOrDefault("", stageBlock)
	if accessLogging := stageBlock.GetBlock("access_log_settings"); accessLogging.IsNotNil() {
		stage.AccessLogging.Metadata = accessLogging.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = accessLogging.GetAttribute("destination_arn").AsStringValueOrDefault("", accessLogging)
	} else {
		stage.AccessLogging.Metadata = stageBlock.GetMetadata()
		stage.AccessLogging.CloudwatchLogGroupARN = types2.StringDefault("", stageBlock.GetMetadata())
	}
	return stage
}
