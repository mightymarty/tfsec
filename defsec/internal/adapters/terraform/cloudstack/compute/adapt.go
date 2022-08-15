package compute

import (
	"encoding/base64"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/cloudstack/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) compute2.Compute {
	return compute2.Compute{
		Instances: adaptInstances(modules),
	}
}

func adaptInstances(modules terraform2.Modules) []compute2.Instance {
	var instances []compute2.Instance
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("cloudstack_instance") {
			instances = append(instances, adaptInstance(resource))
		}
	}
	return instances
}

func adaptInstance(resource *terraform2.Block) compute2.Instance {
	userDataAttr := resource.GetAttribute("user_data")
	var encoded []byte
	var err error

	if userDataAttr.IsNotNil() && userDataAttr.IsString() {
		encoded, err = base64.StdEncoding.DecodeString(userDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(userDataAttr.Value().AsString())
		}
		return compute2.Instance{
			Metadata: resource.GetMetadata(),
			UserData: types.String(string(encoded), userDataAttr.GetMetadata()),
		}
	}

	return compute2.Instance{
		Metadata: resource.GetMetadata(),
		UserData: types.StringDefault("", resource.GetMetadata()),
	}
}
