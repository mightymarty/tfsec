package elasticsearch

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	elasticsearch2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elasticsearch"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) elasticsearch2.Elasticsearch {
	return elasticsearch2.Elasticsearch{
		Domains: adaptDomains(modules),
	}
}

func adaptDomains(modules terraform2.Modules) []elasticsearch2.Domain {
	var domains []elasticsearch2.Domain
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticsearch_domain") {
			domains = append(domains, adaptDomain(resource))
		}
	}
	return domains
}

func adaptDomain(resource *terraform2.Block) elasticsearch2.Domain {
	domain := elasticsearch2.Domain{
		Metadata:   resource.GetMetadata(),
		DomainName: types2.StringDefault("", resource.GetMetadata()),
		LogPublishing: elasticsearch2.LogPublishing{
			Metadata:     resource.GetMetadata(),
			AuditEnabled: types2.BoolDefault(false, resource.GetMetadata()),
		},
		TransitEncryption: elasticsearch2.TransitEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
		},
		AtRestEncryption: elasticsearch2.AtRestEncryption{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
		},
		Endpoint: elasticsearch2.Endpoint{
			Metadata:     resource.GetMetadata(),
			EnforceHTTPS: types2.BoolDefault(false, resource.GetMetadata()),
			TLSPolicy:    types2.StringDefault("", resource.GetMetadata()),
		},
	}

	nameAttr := resource.GetAttribute("domain_name")
	domain.DomainName = nameAttr.AsStringValueOrDefault("", resource)

	for _, logOptionsBlock := range resource.GetBlocks("log_publishing_options") {
		domain.LogPublishing.Metadata = logOptionsBlock.GetMetadata()
		enabledAttr := logOptionsBlock.GetAttribute("enabled")
		enabledVal := enabledAttr.AsBoolValueOrDefault(true, logOptionsBlock)
		logTypeAttr := logOptionsBlock.GetAttribute("log_type")
		if logTypeAttr.Equals("AUDIT_LOGS") {
			domain.LogPublishing.AuditEnabled = enabledVal
		}
	}

	if transitEncryptBlock := resource.GetBlock("node_to_node_encryption"); transitEncryptBlock.IsNotNil() {
		enabledAttr := transitEncryptBlock.GetAttribute("enabled")
		domain.TransitEncryption.Metadata = transitEncryptBlock.GetMetadata()
		domain.TransitEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, transitEncryptBlock)
	}

	if atRestEncryptBlock := resource.GetBlock("encrypt_at_rest"); atRestEncryptBlock.IsNotNil() {
		enabledAttr := atRestEncryptBlock.GetAttribute("enabled")
		domain.AtRestEncryption.Metadata = atRestEncryptBlock.GetMetadata()
		domain.AtRestEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, atRestEncryptBlock)
	}

	if endpointBlock := resource.GetBlock("domain_endpoint_options"); endpointBlock.IsNotNil() {
		domain.Endpoint.Metadata = endpointBlock.GetMetadata()
		enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
		domain.Endpoint.EnforceHTTPS = enforceHTTPSAttr.AsBoolValueOrDefault(true, endpointBlock)
		TLSPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
		domain.Endpoint.TLSPolicy = TLSPolicyAttr.AsStringValueOrDefault("", endpointBlock)
	}

	return domain
}
