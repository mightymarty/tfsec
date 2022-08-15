package appservice

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	appservice2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/appservice"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) appservice2.AppService {
	return appservice2.AppService{
		Services:     adaptServices(modules),
		FunctionApps: adaptFunctionApps(modules),
	}
}

func adaptServices(modules terraform2.Modules) []appservice2.Service {
	var services []appservice2.Service

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_app_service") {
			services = append(services, adaptService(resource))
		}
	}
	return services
}

func adaptFunctionApps(modules terraform2.Modules) []appservice2.FunctionApp {
	var functionApps []appservice2.FunctionApp

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_function_app") {
			functionApps = append(functionApps, adaptFunctionApp(resource))
		}
	}
	return functionApps
}

func adaptService(resource *terraform2.Block) appservice2.Service {
	enableClientCertAttr := resource.GetAttribute("client_cert_enabled")
	enableClientCertVal := enableClientCertAttr.AsBoolValueOrDefault(false, resource)

	identityBlock := resource.GetBlock("identity")
	typeVal := types2.String("", resource.GetMetadata())
	if identityBlock.IsNotNil() {
		typeAttr := identityBlock.GetAttribute("type")
		typeVal = typeAttr.AsStringValueOrDefault("", identityBlock)
	}

	authBlock := resource.GetBlock("auth_settings")
	enabledVal := types2.Bool(false, resource.GetMetadata())
	if authBlock.IsNotNil() {
		enabledAttr := authBlock.GetAttribute("enabled")
		enabledVal = enabledAttr.AsBoolValueOrDefault(false, authBlock)
	}

	siteBlock := resource.GetBlock("site_config")
	enableHTTP2Val := types2.Bool(false, resource.GetMetadata())
	minTLSVersionVal := types2.String("1.2", resource.GetMetadata())
	if siteBlock.IsNotNil() {
		enableHTTP2Attr := siteBlock.GetAttribute("http2_enabled")
		enableHTTP2Val = enableHTTP2Attr.AsBoolValueOrDefault(false, siteBlock)

		minTLSVersionAttr := siteBlock.GetAttribute("min_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("1.2", siteBlock)
	}

	return appservice2.Service{
		Metadata:         resource.GetMetadata(),
		EnableClientCert: enableClientCertVal,
		Identity: struct{ Type types2.StringValue }{
			Type: typeVal,
		},
		Authentication: struct{ Enabled types2.BoolValue }{
			Enabled: enabledVal,
		},
		Site: struct {
			EnableHTTP2       types2.BoolValue
			MinimumTLSVersion types2.StringValue
		}{
			EnableHTTP2:       enableHTTP2Val,
			MinimumTLSVersion: minTLSVersionVal,
		},
	}
}

func adaptFunctionApp(resource *terraform2.Block) appservice2.FunctionApp {
	HTTPSOnlyAttr := resource.GetAttribute("https_only")
	HTTPSOnlyVal := HTTPSOnlyAttr.AsBoolValueOrDefault(false, resource)

	return appservice2.FunctionApp{
		Metadata:  resource.GetMetadata(),
		HTTPSOnly: HTTPSOnlyVal,
	}
}
