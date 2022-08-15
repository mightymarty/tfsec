package terraform

import (
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/aws"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/azure"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/cloudstack"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/digitalocean"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/github"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/kubernetes"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/openstack"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/oracle"
	state2 "github.com/mightymarty/tfsec/defsec/pkg/state"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) *state2.State {
	return &state2.State{
		AWS:          aws.Adapt(modules),
		Azure:        azure.Adapt(modules),
		CloudStack:   cloudstack.Adapt(modules),
		DigitalOcean: digitalocean.Adapt(modules),
		GitHub:       github.Adapt(modules),
		Google:       google.Adapt(modules),
		Kubernetes:   kubernetes.Adapt(modules),
		OpenStack:    openstack.Adapt(modules),
		Oracle:       oracle.Adapt(modules),
	}
}
