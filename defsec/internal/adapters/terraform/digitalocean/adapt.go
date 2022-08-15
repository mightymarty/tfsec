package digitalocean

import (
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/digitalocean/compute"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/digitalocean/spaces"
	digitalocean2 "github.com/mightymarty/tfsec/defsec/pkg/providers/digitalocean"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) digitalocean2.DigitalOcean {
	return digitalocean2.DigitalOcean{
		Compute: compute.Adapt(modules),
		Spaces:  spaces.Adapt(modules),
	}
}
