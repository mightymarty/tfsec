package codebuild

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	codebuild2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/codebuild"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) codebuild2.CodeBuild {
	return codebuild2.CodeBuild{
		Projects: adaptProjects(modules),
	}
}

func adaptProjects(modules terraform2.Modules) []codebuild2.Project {
	var projects []codebuild2.Project
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_codebuild_project") {
			projects = append(projects, adaptProject(resource))
		}
	}
	return projects
}

func adaptProject(resource *terraform2.Block) codebuild2.Project {

	project := codebuild2.Project{
		Metadata: resource.GetMetadata(),
		ArtifactSettings: codebuild2.ArtifactSettings{
			Metadata:          resource.GetMetadata(),
			EncryptionEnabled: types.BoolDefault(true, resource.GetMetadata()),
		},
		SecondaryArtifactSettings: nil,
	}

	var hasArtifacts bool

	if artifactsBlock := resource.GetBlock("artifacts"); artifactsBlock.IsNotNil() {
		project.ArtifactSettings.Metadata = artifactsBlock.GetMetadata()
		typeAttr := artifactsBlock.GetAttribute("type")
		encryptionDisabledAttr := artifactsBlock.GetAttribute("encryption_disabled")
		hasArtifacts = typeAttr.NotEqual("NO_ARTIFACTS")
		if encryptionDisabledAttr.IsTrue() && hasArtifacts {
			project.ArtifactSettings.EncryptionEnabled = types.Bool(false, artifactsBlock.GetMetadata())
		} else {
			project.ArtifactSettings.EncryptionEnabled = types.Bool(true, artifactsBlock.GetMetadata())
		}
	}

	secondaryArtifactBlocks := resource.GetBlocks("secondary_artifacts")
	for _, secondaryArtifactBlock := range secondaryArtifactBlocks {

		secondaryEncryptionEnabled := types.BoolDefault(true, secondaryArtifactBlock.GetMetadata())
		secondaryEncryptionDisabledAttr := secondaryArtifactBlock.GetAttribute("encryption_disabled")
		if secondaryEncryptionDisabledAttr.IsTrue() && hasArtifacts {
			secondaryEncryptionEnabled = types.Bool(false, secondaryArtifactBlock.GetMetadata())
		}

		project.SecondaryArtifactSettings = append(project.SecondaryArtifactSettings, codebuild2.ArtifactSettings{
			Metadata:          secondaryArtifactBlock.GetMetadata(),
			EncryptionEnabled: secondaryEncryptionEnabled,
		})
	}

	return project
}
