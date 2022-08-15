package state

import (
	"reflect"

	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/azure"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/cloudstack"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/digitalocean"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/github"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/google"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/kubernetes"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/openstack"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/oracle"
	"github.com/mightymarty/tfsec/defsec/pkg/rego/convert"
)

type State struct {
	AWS          aws.AWS
	Azure        azure.Azure
	CloudStack   cloudstack.CloudStack
	DigitalOcean digitalocean.DigitalOcean
	GitHub       github.GitHub
	Google       google.Google
	Kubernetes   kubernetes.Kubernetes
	OpenStack    openstack.OpenStack
	Oracle       oracle.Oracle
}

func (s *State) ToRego() interface{} {
	return convert.StructToRego(reflect.ValueOf(s))
}
