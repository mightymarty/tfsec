package compute

import (
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) compute2.Compute {
	return compute2.Compute{
		ProjectMetadata: adaptProjectMetadata(modules),
		Instances:       adaptInstances(modules),
		Disks:           adaptDisks(modules),
		Networks:        adaptNetworks(modules),
		SSLPolicies:     adaptSSLPolicies(modules),
	}
}
