package securitycenter

import (
	securitycenter2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/securitycenter"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) securitycenter2.SecurityCenter {
	return securitycenter2.SecurityCenter{
		Contacts:      adaptContacts(modules),
		Subscriptions: adaptSubscriptions(modules),
	}
}

func adaptContacts(modules terraform2.Modules) []securitycenter2.Contact {
	var contacts []securitycenter2.Contact

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_security_center_contact") {
			contacts = append(contacts, adaptContact(resource))
		}
	}
	return contacts
}

func adaptSubscriptions(modules terraform2.Modules) []securitycenter2.SubscriptionPricing {
	var subscriptions []securitycenter2.SubscriptionPricing

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_security_center_subscription_pricing") {
			subscriptions = append(subscriptions, adaptSubscription(resource))
		}
	}
	return subscriptions
}

func adaptContact(resource *terraform2.Block) securitycenter2.Contact {
	enableAlertNotifAttr := resource.GetAttribute("alert_notifications")
	enableAlertNotifVal := enableAlertNotifAttr.AsBoolValueOrDefault(false, resource)

	phoneAttr := resource.GetAttribute("phone")
	phoneVal := phoneAttr.AsStringValueOrDefault("", resource)

	return securitycenter2.Contact{
		Metadata:                 resource.GetMetadata(),
		EnableAlertNotifications: enableAlertNotifVal,
		Phone:                    phoneVal,
	}
}

func adaptSubscription(resource *terraform2.Block) securitycenter2.SubscriptionPricing {
	tierAttr := resource.GetAttribute("tier")
	tierVal := tierAttr.AsStringValueOrDefault("Free", resource)

	return securitycenter2.SubscriptionPricing{
		Metadata: resource.GetMetadata(),
		Tier:     tierVal,
	}
}
