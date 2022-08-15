package digitalocean

import (
	"github.com/mightymarty/tfsec/defsec/pkg/providers/digitalocean/compute"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}
