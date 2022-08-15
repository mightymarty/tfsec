package bigquery

import (
	bigquery2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/bigquery"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) bigquery2.BigQuery {
	return bigquery2.BigQuery{
		Datasets: adaptDatasets(modules),
	}
}

func adaptDatasets(modules terraform2.Modules) []bigquery2.Dataset {
	var datasets []bigquery2.Dataset
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_bigquery_dataset") {
			datasets = append(datasets, adaptDataset(resource))
		}
	}
	return datasets
}

func adaptDataset(resource *terraform2.Block) bigquery2.Dataset {
	IDAttr := resource.GetAttribute("dataset_id")
	IDVal := IDAttr.AsStringValueOrDefault("", resource)

	var accessGrants []bigquery2.AccessGrant

	accessBlocks := resource.GetBlocks("access")
	for _, accessBlock := range accessBlocks {
		roleAttr := accessBlock.GetAttribute("role")
		roleVal := roleAttr.AsStringValueOrDefault("", accessBlock)

		domainAttr := accessBlock.GetAttribute("domain")
		domainVal := domainAttr.AsStringValueOrDefault("", accessBlock)

		specialGrAttr := accessBlock.GetAttribute("special_group")
		specialGrVal := specialGrAttr.AsStringValueOrDefault("", accessBlock)

		accessGrants = append(accessGrants, bigquery2.AccessGrant{
			Metadata:     accessBlock.GetMetadata(),
			Role:         roleVal,
			Domain:       domainVal,
			SpecialGroup: specialGrVal,
		})
	}

	return bigquery2.Dataset{
		Metadata:     resource.GetMetadata(),
		ID:           IDVal,
		AccessGrants: accessGrants,
	}
}
