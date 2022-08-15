package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	types.Metadata
	UserData types.StringValue // not b64 encoded pls
}
