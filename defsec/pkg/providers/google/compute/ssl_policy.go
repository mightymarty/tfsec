package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type SSLPolicy struct {
	types.Metadata
	Name              types.StringValue
	Profile           types.StringValue
	MinimumTLSVersion types.StringValue
}
