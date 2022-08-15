package apigateway

import (
	apigateway2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway"
	v12 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v1"
	v22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway/v2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) apigateway2.APIGateway {
	return apigateway2.APIGateway{
		V1: v12.APIGateway{
			APIs:        adaptAPIsV1(modules),
			DomainNames: adaptDomainNamesV1(modules),
		},
		V2: v22.APIGateway{
			APIs:        adaptAPIsV2(modules),
			DomainNames: adaptDomainNamesV2(modules),
		},
	}
}
