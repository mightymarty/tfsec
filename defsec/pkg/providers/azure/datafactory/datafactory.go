package datafactory

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	types.Metadata
	EnablePublicNetwork types.BoolValue
}
