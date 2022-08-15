package ecr

import (
	"github.com/liamg/iamgo"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	ecr2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ecr"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) ecr2.ECR {
	return ecr2.ECR{
		Repositories: adaptRepositories(modules),
	}
}

func adaptRepositories(modules terraform2.Modules) []ecr2.Repository {
	var repositories []ecr2.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_ecr_repository") {
			repositories = append(repositories, adaptRepository(resource, module))
		}
	}
	return repositories
}

func adaptRepository(resource *terraform2.Block, module *terraform2.Module) ecr2.Repository {
	repo := ecr2.Repository{
		Metadata: resource.GetMetadata(),
		ImageScanning: ecr2.ImageScanning{
			Metadata:   resource.GetMetadata(),
			ScanOnPush: types2.BoolDefault(false, resource.GetMetadata()),
		},
		ImageTagsImmutable: types2.BoolDefault(false, resource.GetMetadata()),
		Policies:           nil,
		Encryption: ecr2.Encryption{
			Metadata: resource.GetMetadata(),
			Type:     types2.StringDefault("AES256", resource.GetMetadata()),
			KMSKeyID: types2.StringDefault("", resource.GetMetadata()),
		},
	}

	if imageScanningBlock := resource.GetBlock("image_scanning_configuration"); imageScanningBlock.IsNotNil() {
		repo.ImageScanning.Metadata = imageScanningBlock.GetMetadata()
		scanOnPushAttr := imageScanningBlock.GetAttribute("scan_on_push")
		repo.ImageScanning.ScanOnPush = scanOnPushAttr.AsBoolValueOrDefault(false, imageScanningBlock)
	}

	mutabilityAttr := resource.GetAttribute("image_tag_mutability")
	if mutabilityAttr.Equals("IMMUTABLE") {
		repo.ImageTagsImmutable = types2.Bool(true, mutabilityAttr.GetMetadata())
	} else if mutabilityAttr.Equals("MUTABLE") {
		repo.ImageTagsImmutable = types2.Bool(false, mutabilityAttr.GetMetadata())
	}

	policyBlocks := module.GetReferencingResources(resource, "aws_ecr_repository_policy", "repository")
	for _, policyRes := range policyBlocks {
		if policyAttr := policyRes.GetAttribute("policy"); policyAttr.IsString() {

			parsed, err := iamgo.ParseString(policyAttr.Value().AsString())
			if err != nil {
				continue
			}

			policy := iam.Policy{
				Metadata: policyRes.GetMetadata(),
				Name:     types2.StringDefault("", policyRes.GetMetadata()),
				Document: iam.Document{
					Parsed:   *parsed,
					Metadata: policyAttr.GetMetadata(),
				},
			}

			repo.Policies = append(repo.Policies, policy)
		}
	}

	if encryptBlock := resource.GetBlock("encryption_configuration"); encryptBlock.IsNotNil() {
		repo.Encryption.Metadata = encryptBlock.GetMetadata()
		encryptionTypeAttr := encryptBlock.GetAttribute("encryption_type")
		repo.Encryption.Type = encryptionTypeAttr.AsStringValueOrDefault("AES256", encryptBlock)

		kmsKeyAttr := encryptBlock.GetAttribute("kms_key")
		repo.Encryption.KMSKeyID = kmsKeyAttr.AsStringValueOrDefault("", encryptBlock)
		if kmsKeyAttr.IsResourceBlockReference("aws_kms_key") {
			if keyBlock, err := module.GetReferencedBlock(kmsKeyAttr, encryptBlock); err == nil {
				repo.Encryption.KMSKeyID = types2.String(keyBlock.FullName(), keyBlock.GetMetadata())
			}
		}
	}

	return repo
}
