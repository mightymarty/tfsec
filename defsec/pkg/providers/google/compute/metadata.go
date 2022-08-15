package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type ProjectMetadata struct {
	types.Metadata
	EnableOSLogin types.BoolValue
}
