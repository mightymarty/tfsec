package keyvault

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	keyvault2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/keyvault"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"time"
)

func Adapt(modules terraform2.Modules) keyvault2.KeyVault {
	adapter := adapter{
		vaultSecretIDs: modules.GetChildResourceIDMapByType("azurerm_key_vault_secret"),
		vaultKeyIDs:    modules.GetChildResourceIDMapByType("azurerm_key_vault_key"),
	}

	return keyvault2.KeyVault{
		Vaults: adapter.adaptVaults(modules),
	}
}

type adapter struct {
	vaultSecretIDs terraform2.ResourceIDResolutions
	vaultKeyIDs    terraform2.ResourceIDResolutions
}

func (a *adapter) adaptVaults(modules terraform2.Modules) []keyvault2.Vault {

	var vaults []keyvault2.Vault
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_key_vault") {
			vaults = append(vaults, a.adaptVault(resource, module))

		}
	}

	orphanResources := modules.GetResourceByIDs(a.vaultSecretIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := keyvault2.Vault{
			Metadata:                types2.NewUnmanagedMetadata(),
			Secrets:                 nil,
			Keys:                    nil,
			EnablePurgeProtection:   types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			SoftDeleteRetentionDays: types2.IntDefault(0, types2.NewUnmanagedMetadata()),
			NetworkACLs: keyvault2.NetworkACLs{
				Metadata:      types2.NewUnmanagedMetadata(),
				DefaultAction: types2.StringDefault("", types2.NewUnmanagedMetadata()),
			},
		}
		for _, secretResource := range orphanResources {
			orphanage.Secrets = append(orphanage.Secrets, adaptSecret(secretResource))
		}
		vaults = append(vaults, orphanage)
	}

	orphanResources = modules.GetResourceByIDs(a.vaultKeyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := keyvault2.Vault{
			Metadata:                types2.NewUnmanagedMetadata(),
			Secrets:                 nil,
			Keys:                    nil,
			EnablePurgeProtection:   types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
			SoftDeleteRetentionDays: types2.IntDefault(0, types2.NewUnmanagedMetadata()),
			NetworkACLs: keyvault2.NetworkACLs{
				Metadata:      types2.NewUnmanagedMetadata(),
				DefaultAction: types2.StringDefault("", types2.NewUnmanagedMetadata()),
			},
		}
		for _, secretResource := range orphanResources {
			orphanage.Keys = append(orphanage.Keys, adaptKey(secretResource))
		}
		vaults = append(vaults, orphanage)
	}

	return vaults
}

func (a *adapter) adaptVault(resource *terraform2.Block, module *terraform2.Module) keyvault2.Vault {
	var keys []keyvault2.Key
	var secrets []keyvault2.Secret

	defaultActionVal := types2.StringDefault("", resource.GetMetadata())

	secretBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_secret", "key_vault_id")
	for _, secretBlock := range secretBlocks {
		a.vaultSecretIDs.Resolve(secretBlock.ID())
		secrets = append(secrets, adaptSecret(secretBlock))
	}

	keyBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_key", "key_vault_id")
	for _, keyBlock := range keyBlocks {
		a.vaultKeyIDs.Resolve(keyBlock.ID())
		keys = append(keys, adaptKey(keyBlock))
	}

	purgeProtectionAttr := resource.GetAttribute("purge_protection_enabled")
	purgeProtectionVal := purgeProtectionAttr.AsBoolValueOrDefault(false, resource)

	softDeleteRetentionDaysAttr := resource.GetAttribute("soft_delete_retention_days")
	softDeleteRetentionDaysVal := softDeleteRetentionDaysAttr.AsIntValueOrDefault(0, resource)

	aclMetadata := types2.NewUnmanagedMetadata()
	if aclBlock := resource.GetBlock("network_acls"); aclBlock.IsNotNil() {
		aclMetadata = aclBlock.GetMetadata()
		defaultActionAttr := aclBlock.GetAttribute("default_action")
		defaultActionVal = defaultActionAttr.AsStringValueOrDefault("", resource.GetBlock("network_acls"))
	}

	return keyvault2.Vault{
		Metadata:                resource.GetMetadata(),
		Secrets:                 secrets,
		Keys:                    keys,
		EnablePurgeProtection:   purgeProtectionVal,
		SoftDeleteRetentionDays: softDeleteRetentionDaysVal,
		NetworkACLs: keyvault2.NetworkACLs{
			Metadata:      aclMetadata,
			DefaultAction: defaultActionVal,
		},
	}
}

func adaptSecret(resource *terraform2.Block) keyvault2.Secret {
	contentTypeAttr := resource.GetAttribute("content_type")
	contentTypeVal := contentTypeAttr.AsStringValueOrDefault("", resource)

	expiryDateAttr := resource.GetAttribute("expiration_date")
	expiryDateVal := types2.TimeDefault(time.Time{}, resource.GetMetadata())

	if expiryDateAttr.IsString() {
		expiryDateString := expiryDateAttr.Value().AsString()
		if expiryDate, err := time.Parse(time.RFC3339, expiryDateString); err == nil {
			expiryDateVal = types2.Time(expiryDate, expiryDateAttr.GetMetadata())
		}
	} else if expiryDateAttr.IsNotNil() {
		expiryDateVal = types2.TimeUnresolvable(expiryDateAttr.GetMetadata())
	}

	return keyvault2.Secret{
		Metadata:    resource.GetMetadata(),
		ContentType: contentTypeVal,
		ExpiryDate:  expiryDateVal,
	}
}

func adaptKey(resource *terraform2.Block) keyvault2.Key {
	expiryDateAttr := resource.GetAttribute("expiration_date")
	expiryDateVal := types2.TimeDefault(time.Time{}, resource.GetMetadata())

	if expiryDateAttr.IsNotNil() {
		expiryDateString := expiryDateAttr.Value().AsString()
		if expiryDate, err := time.Parse(time.RFC3339, expiryDateString); err == nil {
			expiryDateVal = types2.Time(expiryDate, expiryDateAttr.GetMetadata())
		}
	}

	return keyvault2.Key{
		Metadata:   resource.GetMetadata(),
		ExpiryDate: expiryDateVal,
	}
}
