package compute

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type Network struct {
	types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
