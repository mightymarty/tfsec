package github

import (
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/github/repositories"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/github/secrets"
	github2 "github.com/mightymarty/tfsec/defsec/pkg/providers/github"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) github2.GitHub {
	return github2.GitHub{
		Repositories:       repositories.Adapt(modules),
		EnvironmentSecrets: secrets.Adapt(modules),
	}
}
