package ecs

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	ecs2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ecs"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) ecs2.ECS {
	return ecs2.ECS{
		Clusters:        adaptClusters(modules),
		TaskDefinitions: adaptTaskDefinitions(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []ecs2.Cluster {
	var clusters []ecs2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecs_cluster") {
			clusters = append(clusters, adaptClusterResource(resource))
		}
	}
	return clusters
}

func adaptClusterResource(resourceBlock *terraform2.Block) ecs2.Cluster {
	return ecs2.Cluster{
		Metadata: resourceBlock.GetMetadata(),
		Settings: adaptClusterSettings(resourceBlock),
	}
}

func adaptClusterSettings(resourceBlock *terraform2.Block) ecs2.ClusterSettings {
	settings := ecs2.ClusterSettings{
		Metadata:                 resourceBlock.GetMetadata(),
		ContainerInsightsEnabled: types.BoolDefault(false, resourceBlock.GetMetadata()),
	}

	if settingBlock := resourceBlock.GetBlock("setting"); settingBlock.IsNotNil() {
		settings.Metadata = settingBlock.GetMetadata()
		if settingBlock.GetAttribute("name").Equals("containerInsights") {
			insightsAttr := settingBlock.GetAttribute("value")
			settings.ContainerInsightsEnabled = types.Bool(insightsAttr.Equals("enabled"), settingBlock.GetMetadata())
			if insightsAttr.IsNotNil() {
				settings.ContainerInsightsEnabled = types.Bool(insightsAttr.Equals("enabled"), insightsAttr.GetMetadata())
			}
		}
	}
	return settings
}

func adaptTaskDefinitions(modules terraform2.Modules) []ecs2.TaskDefinition {
	var taskDefinitions []ecs2.TaskDefinition
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecs_task_definition") {
			taskDefinitions = append(taskDefinitions, adaptTaskDefinitionResource(resource))
		}
	}
	return taskDefinitions
}

func adaptTaskDefinitionResource(resourceBlock *terraform2.Block) ecs2.TaskDefinition {

	var definitions []ecs2.ContainerDefinition
	if ct := resourceBlock.GetAttribute("container_definitions"); ct != nil && ct.IsString() {
		definitions, _ = ecs2.CreateDefinitionsFromString(resourceBlock.GetMetadata(), ct.Value().AsString())
	}

	return ecs2.TaskDefinition{
		Metadata:             resourceBlock.GetMetadata(),
		Volumes:              adaptVolumes(resourceBlock),
		ContainerDefinitions: definitions,
	}
}

func adaptVolumes(resourceBlock *terraform2.Block) []ecs2.Volume {
	if volumeBlocks := resourceBlock.GetBlocks("volume"); len(volumeBlocks) > 0 {
		var volumes []ecs2.Volume
		for _, volumeBlock := range volumeBlocks {
			volumes = append(volumes, ecs2.Volume{
				Metadata:               volumeBlock.GetMetadata(),
				EFSVolumeConfiguration: adaptEFSVolumeConfiguration(volumeBlock),
			})
		}
		return volumes
	}

	return []ecs2.Volume{}
}

func adaptEFSVolumeConfiguration(volumeBlock *terraform2.Block) ecs2.EFSVolumeConfiguration {
	EFSVolumeConfiguration := ecs2.EFSVolumeConfiguration{
		Metadata:                 volumeBlock.GetMetadata(),
		TransitEncryptionEnabled: types.BoolDefault(true, volumeBlock.GetMetadata()),
	}

	if EFSConfigBlock := volumeBlock.GetBlock("efs_volume_configuration"); EFSConfigBlock.IsNotNil() {
		EFSVolumeConfiguration.Metadata = EFSConfigBlock.GetMetadata()
		transitEncryptionAttr := EFSConfigBlock.GetAttribute("transit_encryption")
		EFSVolumeConfiguration.TransitEncryptionEnabled = types.Bool(transitEncryptionAttr.Equals("ENABLED"), EFSConfigBlock.GetMetadata())
		if transitEncryptionAttr.IsNotNil() {
			EFSVolumeConfiguration.TransitEncryptionEnabled = types.Bool(transitEncryptionAttr.Equals("ENABLED"), transitEncryptionAttr.GetMetadata())
		}
	}

	return EFSVolumeConfiguration
}
