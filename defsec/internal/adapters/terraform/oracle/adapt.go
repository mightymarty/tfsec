package oracle

import (
	oracle2 "github.com/mightymarty/tfsec/defsec/pkg/providers/oracle"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) oracle2.Oracle {
	return oracle2.Oracle{
		Compute: adaptCompute(modules),
	}
}

func adaptCompute(modules terraform2.Modules) oracle2.Compute {
	var compute oracle2.Compute

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("opc_compute_ip_address_reservation") {

			addressPoolAttr := resource.GetAttribute("ip_address_pool")
			addressPoolVal := addressPoolAttr.AsStringValueOrDefault("", resource)
			compute.AddressReservations = append(compute.AddressReservations, oracle2.AddressReservation{
				Metadata: resource.GetMetadata(),
				Pool:     addressPoolVal,
			})
		}
	}
	return compute
}
