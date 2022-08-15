package apigateway

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	v22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptDomainNamesV2(modules terraform2.Modules) []v22.DomainName {

	var domainNames []v22.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_apigatewayv2_domain_name") {
			domainName := v22.DomainName{
				Metadata:       nameBlock.GetMetadata(),
				Name:           nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock),
				SecurityPolicy: types.StringDefault("TLS_1_0", nameBlock.GetMetadata()),
			}
			if config := nameBlock.GetBlock("domain_name_configuration"); config.IsNotNil() {
				domainName.SecurityPolicy = config.GetAttribute("security_policy").AsStringValueOrDefault("TLS_1_0", config)
			}
			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}
