package compute

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	compute2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/compute"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"github.com/zclconf/go-cty/cty"
)

func adaptProjectMetadata(modules terraform2.Modules) compute2.ProjectMetadata {
	metadata := compute2.ProjectMetadata{
		Metadata: types2.NewUnmanagedMetadata(),
		EnableOSLogin: types2.BoolUnresolvable(
			types2.NewUnmanagedMetadata(),
		),
	}
	for _, metadataBlock := range modules.GetResourcesByType("google_compute_project_metadata") {
		metadata.Metadata = metadataBlock.GetMetadata()
		if metadataAttr := metadataBlock.GetAttribute("metadata"); metadataAttr.IsNotNil() {
			if val := metadataAttr.MapValue("enable-oslogin"); val.Type() == cty.Bool {
				metadata.EnableOSLogin = types2.BoolExplicit(val.True(), metadataAttr.GetMetadata())
			}
		}
	}
	return metadata
}
