package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type SubNetwork struct {
	types.Metadata
	Name           types.StringValue
	EnableFlowLogs types.BoolValue
}
