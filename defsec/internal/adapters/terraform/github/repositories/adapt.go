package repositories

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	github2 "github.com/mightymarty/tfsec/defsec/pkg/providers/github"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) []github2.Repository {
	return adaptRepositories(modules)
}

func adaptRepositories(modules terraform2.Modules) []github2.Repository {
	var repositories []github2.Repository
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_repository") {
			repositories = append(repositories, adaptRepository(resource))
		}
	}
	return repositories
}

func adaptRepository(resource *terraform2.Block) github2.Repository {

	repo := github2.Repository{
		Metadata:            resource.GetMetadata(),
		Public:              types.Bool(true, resource.GetMetadata()),
		VulnerabilityAlerts: resource.GetAttribute("vulnerability_alerts").AsBoolValueOrDefault(false, resource),
		Archived:            resource.GetAttribute("archived").AsBoolValueOrDefault(false, resource),
	}

	privateAttr := resource.GetAttribute("private")
	if privateAttr.IsTrue() {
		repo.Public = types.Bool(false, privateAttr.GetMetadata())
	} else if privateAttr.IsFalse() {
		repo.Public = types.Bool(true, privateAttr.GetMetadata())
	}

	// visibility overrides private
	visibilityAttr := resource.GetAttribute("visibility")
	if visibilityAttr.Equals("private") || visibilityAttr.Equals("internal") {
		repo.Public = types.Bool(false, visibilityAttr.GetMetadata())
	} else if visibilityAttr.Equals("public") {
		repo.Public = types.Bool(true, visibilityAttr.GetMetadata())
	}

	return repo
}
