package cloudstack

import (
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/cloudstack/compute"
	cloudstack2 "github.com/mightymarty/tfsec/defsec/pkg/providers/cloudstack"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) cloudstack2.CloudStack {
	return cloudstack2.CloudStack{
		Compute: compute.Adapt(modules),
	}
}
