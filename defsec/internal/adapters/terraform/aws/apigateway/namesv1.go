package apigateway

import (
	v12 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v1"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptDomainNamesV1(modules terraform2.Modules) []v12.DomainName {

	var domainNames []v12.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_api_gateway_domain_name") {
			domainName := v12.DomainName{
				Metadata:       nameBlock.GetMetadata(),
				Name:           nameBlock.GetAttribute("domain_name").AsStringValueOrDefault("", nameBlock),
				SecurityPolicy: nameBlock.GetAttribute("security_policy").AsStringValueOrDefault("TLS_1_0", nameBlock),
			}
			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}
