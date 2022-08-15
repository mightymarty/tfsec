package openstack

import (
	openstack2 "github.com/mightymarty/tfsec/defsec/pkg/providers/openstack"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) openstack2.OpenStack {
	return openstack2.OpenStack{
		Compute:    adaptCompute(modules),
		Networking: adaptNetworking(modules),
	}
}

func adaptCompute(modules terraform2.Modules) openstack2.Compute {
	var compute openstack2.Compute

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("openstack_compute_instance_v2") {
			compute.Instances = append(compute.Instances, adaptInstance(resource))
		}
	}
	compute.Firewall = adaptFirewall(modules)

	return compute
}

func adaptInstance(resourceBlock *terraform2.Block) openstack2.Instance {
	adminPassAttr := resourceBlock.GetAttribute("admin_pass")
	adminPassVal := adminPassAttr.AsStringValueOrDefault("", resourceBlock)

	return openstack2.Instance{
		Metadata:      resourceBlock.GetMetadata(),
		AdminPassword: adminPassVal,
	}
}

func adaptFirewall(modules terraform2.Modules) openstack2.Firewall {
	var firewall openstack2.Firewall

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("openstack_fw_rule_v1") {

			sourceAttr := resource.GetAttribute("source_ip_address")
			sourceVal := sourceAttr.AsStringValueOrDefault("", resource)

			destinationAttr := resource.GetAttribute("destination_ip_address")
			destinationVal := destinationAttr.AsStringValueOrDefault("", resource)

			sourcePortAttr := resource.GetAttribute("source_port")
			sourcePortVal := sourcePortAttr.AsStringValueOrDefault("", resource)

			destinationPortAttr := resource.GetAttribute("destination_port")
			destinationPortVal := destinationPortAttr.AsStringValueOrDefault("", resource)

			enabledAttr := resource.GetAttribute("enabled")
			enabledVal := enabledAttr.AsBoolValueOrDefault(true, resource)

			if resource.GetAttribute("action").Equals("allow") {
				firewall.AllowRules = append(firewall.AllowRules, openstack2.FirewallRule{
					Metadata:        resource.GetMetadata(),
					Source:          sourceVal,
					Destination:     destinationVal,
					SourcePort:      sourcePortVal,
					DestinationPort: destinationPortVal,
					Enabled:         enabledVal,
				})
			} else if resource.GetAttribute("action").Equals("deny") {
				firewall.DenyRules = append(firewall.DenyRules, openstack2.FirewallRule{
					Metadata:        resource.GetMetadata(),
					Source:          sourceVal,
					Destination:     destinationVal,
					SourcePort:      sourcePortVal,
					DestinationPort: destinationPortVal,
					Enabled:         enabledVal,
				})
			}
		}
	}
	return firewall
}
