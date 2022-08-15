package ssm

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	ssm2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ssm"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) ssm2.SSM {
	return ssm2.SSM{
		Secrets: adaptSecrets(modules),
	}
}

func adaptSecrets(modules terraform2.Modules) []ssm2.Secret {
	var secrets []ssm2.Secret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_secretsmanager_secret") {
			secrets = append(secrets, adaptSecret(resource, module))
		}
	}
	return secrets
}

func adaptSecret(resource *terraform2.Block, module *terraform2.Module) ssm2.Secret {
	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("alias/aws/secretsmanager", resource)

	if KMSKeyIDAttr.IsResourceBlockReference("aws_kms_key") {
		kmsBlock, err := module.GetReferencedBlock(KMSKeyIDAttr, resource)
		if err == nil {
			KMSKeyIDVal = types.String(kmsBlock.FullName(), kmsBlock.GetMetadata())
		}
	}

	return ssm2.Secret{
		Metadata: resource.GetMetadata(),
		KMSKeyID: KMSKeyIDVal,
	}
}
