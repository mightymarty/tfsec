package kinesis

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	kinesis2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/kinesis"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) kinesis2.Kinesis {
	return kinesis2.Kinesis{
		Streams: adaptStreams(modules),
	}
}

func adaptStreams(modules terraform2.Modules) []kinesis2.Stream {
	var streams []kinesis2.Stream
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_kinesis_stream") {
			streams = append(streams, adaptStream(resource))
		}
	}
	return streams
}

func adaptStream(resource *terraform2.Block) kinesis2.Stream {

	stream := kinesis2.Stream{
		Metadata: resource.GetMetadata(),
		Encryption: kinesis2.Encryption{
			Metadata: resource.GetMetadata(),
			Type:     types.StringDefault("NONE", resource.GetMetadata()),
			KMSKeyID: types.StringDefault("", resource.GetMetadata()),
		},
	}

	encryptionTypeAttr := resource.GetAttribute("encryption_type")
	stream.Encryption.Type = encryptionTypeAttr.AsStringValueOrDefault("NONE", resource)
	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	stream.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValueOrDefault("", resource)
	return stream
}
