package cloudfront

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	cloudfront2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudfront"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) cloudfront2.Cloudfront {
	return cloudfront2.Cloudfront{
		Distributions: adaptDistributions(modules),
	}
}

func adaptDistributions(modules terraform2.Modules) []cloudfront2.Distribution {
	var distributions []cloudfront2.Distribution
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_cloudfront_distribution") {
			distributions = append(distributions, adaptDistribution(resource))
		}
	}
	return distributions
}

func adaptDistribution(resource *terraform2.Block) cloudfront2.Distribution {

	distribution := cloudfront2.Distribution{
		Metadata: resource.GetMetadata(),
		WAFID:    types.StringDefault("", resource.GetMetadata()),
		Logging: cloudfront2.Logging{
			Metadata: resource.GetMetadata(),
			Bucket:   types.StringDefault("", resource.GetMetadata()),
		},
		DefaultCacheBehaviour: cloudfront2.CacheBehaviour{
			Metadata:             resource.GetMetadata(),
			ViewerProtocolPolicy: types.String("allow-all", resource.GetMetadata()),
		},
		OrdererCacheBehaviours: nil,
		ViewerCertificate: cloudfront2.ViewerCertificate{
			Metadata:               resource.GetMetadata(),
			MinimumProtocolVersion: types.StringDefault("TLSv1", resource.GetMetadata()),
		},
	}

	distribution.WAFID = resource.GetAttribute("web_acl_id").AsStringValueOrDefault("", resource)

	if loggingBlock := resource.GetBlock("logging_config"); loggingBlock.IsNotNil() {
		distribution.Logging.Metadata = loggingBlock.GetMetadata()
		bucketAttr := loggingBlock.GetAttribute("bucket")
		distribution.Logging.Bucket = bucketAttr.AsStringValueOrDefault("", loggingBlock)
	}

	if defaultCacheBlock := resource.GetBlock("default_cache_behavior"); defaultCacheBlock.IsNotNil() {
		distribution.DefaultCacheBehaviour.Metadata = defaultCacheBlock.GetMetadata()
		viewerProtocolPolicyAttr := defaultCacheBlock.GetAttribute("viewer_protocol_policy")
		distribution.DefaultCacheBehaviour.ViewerProtocolPolicy = viewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", defaultCacheBlock)
	}

	orderedCacheBlocks := resource.GetBlocks("ordered_cache_behavior")
	for _, orderedCacheBlock := range orderedCacheBlocks {
		viewerProtocolPolicyAttr := orderedCacheBlock.GetAttribute("viewer_protocol_policy")
		viewerProtocolPolicyVal := viewerProtocolPolicyAttr.AsStringValueOrDefault("allow-all", orderedCacheBlock)
		distribution.OrdererCacheBehaviours = append(distribution.OrdererCacheBehaviours, cloudfront2.CacheBehaviour{
			Metadata:             orderedCacheBlock.GetMetadata(),
			ViewerProtocolPolicy: viewerProtocolPolicyVal,
		})
	}

	if viewerCertBlock := resource.GetBlock("viewer_certificate"); viewerCertBlock.IsNotNil() {
		distribution.ViewerCertificate.Metadata = viewerCertBlock.GetMetadata()
		minProtocolAttr := viewerCertBlock.GetAttribute("minimum_protocol_version")
		distribution.ViewerCertificate.MinimumProtocolVersion = minProtocolAttr.AsStringValueOrDefault("TLSv1", viewerCertBlock)
	}

	return distribution
}
