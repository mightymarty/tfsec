package kinesis

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type Kinesis struct {
	Streams []Stream
}

type Stream struct {
	types.Metadata
	Encryption Encryption
}

const (
	EncryptionTypeKMS = "KMS"
)

type Encryption struct {
	types.Metadata
	Type     types.StringValue
	KMSKeyID types.StringValue
}
