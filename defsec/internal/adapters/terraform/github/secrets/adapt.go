package secrets

import (
	github2 "github.com/mightymarty/tfsec/defsec/pkg/providers/github"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) []github2.EnvironmentSecret {
	return adaptSecrets(modules)
}

func adaptSecrets(modules terraform2.Modules) []github2.EnvironmentSecret {
	var secrets []github2.EnvironmentSecret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_actions_environment_secret") {
			secrets = append(secrets, adaptSecret(resource))
		}
	}
	return secrets
}

func adaptSecret(resource *terraform2.Block) github2.EnvironmentSecret {
	secret := github2.EnvironmentSecret{
		Metadata:       resource.GetMetadata(),
		Repository:     resource.GetAttribute("repository").AsStringValueOrDefault("", resource),
		Environment:    resource.GetAttribute("environment").AsStringValueOrDefault("", resource),
		SecretName:     resource.GetAttribute("secret_name").AsStringValueOrDefault("", resource),
		PlainTextValue: resource.GetAttribute("plaintext_value").AsStringValueOrDefault("", resource),
		EncryptedValue: resource.GetAttribute("encrypted_value").AsStringValueOrDefault("", resource),
	}
	return secret
}
