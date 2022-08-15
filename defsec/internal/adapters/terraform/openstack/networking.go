package openstack

import (
	"github.com/google/uuid"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	openstack2 "github.com/mightymarty/tfsec/defsec/pkg/providers/openstack"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptNetworking(modules terraform2.Modules) openstack2.Networking {
	return openstack2.Networking{
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptSecurityGroups(modules terraform2.Modules) []openstack2.SecurityGroup {
	groupMap := make(map[string]openstack2.SecurityGroup)
	for _, groupBlock := range modules.GetResourcesByType("openstack_networking_secgroup_v2") {
		group := openstack2.SecurityGroup{
			Metadata:    groupBlock.GetMetadata(),
			Name:        groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock),
			Description: groupBlock.GetAttribute("description").AsStringValueOrDefault("", groupBlock),
			Rules:       nil,
		}
		groupMap[groupBlock.ID()] = group
	}

	for _, ruleBlock := range modules.GetResourcesByType("openstack_networking_secgroup_rule_v2") {
		rule := openstack2.SecurityGroupRule{
			Metadata:  ruleBlock.GetMetadata(),
			IsIngress: types2.Bool(true, ruleBlock.GetMetadata()),
			EtherType: types2.IntDefault(4, ruleBlock.GetMetadata()),
			Protocol:  ruleBlock.GetAttribute("protocol").AsStringValueOrDefault("tcp", ruleBlock),
			PortMin:   ruleBlock.GetAttribute("port_range_min").AsIntValueOrDefault(0, ruleBlock),
			PortMax:   ruleBlock.GetAttribute("port_range_max").AsIntValueOrDefault(0, ruleBlock),
			CIDR:      ruleBlock.GetAttribute("remote_ip_prefix").AsStringValueOrDefault("", ruleBlock),
		}

		switch etherType := ruleBlock.GetAttribute("ethertype"); {
		case etherType.Equals("IPv4"):
			rule.EtherType = types2.Int(4, etherType.GetMetadata())
		case etherType.Equals("IPv6"):
			rule.EtherType = types2.Int(6, etherType.GetMetadata())
		}

		switch direction := ruleBlock.GetAttribute("direction"); {
		case direction.Equals("egress"):
			rule.IsIngress = types2.Bool(false, direction.GetMetadata())
		case direction.Equals("ingress"):
			rule.IsIngress = types2.Bool(true, direction.GetMetadata())
		}

		groupID := ruleBlock.GetAttribute("security_group_id")
		if refBlock, err := modules.GetReferencedBlock(groupID, ruleBlock); err == nil {
			if group, ok := groupMap[refBlock.ID()]; ok {
				group.Rules = append(group.Rules, rule)
				groupMap[refBlock.ID()] = group
				continue
			}
		}

		var group openstack2.SecurityGroup
		group.Metadata = types2.NewUnmanagedMetadata()
		group.Rules = append(group.Rules, rule)
		groupMap[uuid.NewString()] = group

	}

	var groups []openstack2.SecurityGroup
	for _, group := range groupMap {
		groups = append(groups, group)
	}
	return groups
}
