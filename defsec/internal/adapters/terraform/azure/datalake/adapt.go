package datalake

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	datalake2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/datalake"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) datalake2.DataLake {
	return datalake2.DataLake{
		Stores: adaptStores(modules),
	}
}

func adaptStores(modules terraform2.Modules) []datalake2.Store {
	var stores []datalake2.Store

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_data_lake_store") {
			stores = append(stores, adaptStore(resource))
		}
	}
	return stores
}

func adaptStore(resource *terraform2.Block) datalake2.Store {
	store := datalake2.Store{
		Metadata:         resource.GetMetadata(),
		EnableEncryption: types.BoolDefault(true, resource.GetMetadata()),
	}
	encryptionStateAttr := resource.GetAttribute("encryption_state")
	if encryptionStateAttr.Equals("Disabled") {
		store.EnableEncryption = types.Bool(false, encryptionStateAttr.GetMetadata())
	} else if encryptionStateAttr.Equals("Enabled") {
		store.EnableEncryption = types.Bool(true, encryptionStateAttr.GetMetadata())
	}
	return store
}
