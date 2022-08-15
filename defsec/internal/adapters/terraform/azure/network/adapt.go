package network

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	network2 "github.com/mightymarty/tfsec/defsec/pkg/providers/azure/network"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func Adapt(modules terraform2.Modules) network2.Network {
	return network2.Network{
		SecurityGroups: (&adapter{
			modules: modules,
			groups:  make(map[string]network2.SecurityGroup),
		}).adaptSecurityGroups(),
		NetworkWatcherFlowLogs: adaptWatcherLogs(modules),
	}
}

type adapter struct {
	modules terraform2.Modules
	groups  map[string]network2.SecurityGroup
}

func (a *adapter) adaptSecurityGroups() []network2.SecurityGroup {

	for _, module := range a.modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_security_group") {
			a.adaptSecurityGroup(resource)
		}
	}

	for _, ruleBlock := range a.modules.GetResourcesByType("azurerm_network_security_rule") {
		rule := a.adaptSGRule(ruleBlock)

		groupAttr := ruleBlock.GetAttribute("network_security_group_name")
		if groupAttr.IsNotNil() {
			if referencedBlock, err := a.modules.GetReferencedBlock(groupAttr, ruleBlock); err == nil {
				if group, ok := a.groups[referencedBlock.ID()]; ok {
					group.Rules = append(group.Rules, rule)
					a.groups[referencedBlock.ID()] = group
					continue
				}
			}

		}

		a.groups[uuid.NewString()] = network2.SecurityGroup{
			Metadata: types2.NewUnmanagedMetadata(),
			Rules:    []network2.SecurityGroupRule{rule},
		}
	}

	var securityGroups []network2.SecurityGroup
	for _, group := range a.groups {
		securityGroups = append(securityGroups, group)
	}

	return securityGroups
}

func adaptWatcherLogs(modules terraform2.Modules) []network2.NetworkWatcherFlowLog {
	var watcherLogs []network2.NetworkWatcherFlowLog

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_network_watcher_flow_log") {
			watcherLogs = append(watcherLogs, adaptWatcherLog(resource))
		}
	}
	return watcherLogs
}

func (a *adapter) adaptSecurityGroup(resource *terraform2.Block) {
	var rules []network2.SecurityGroupRule
	for _, ruleBlock := range resource.GetBlocks("security_rule") {
		rules = append(rules, a.adaptSGRule(ruleBlock))
	}
	a.groups[resource.ID()] = network2.SecurityGroup{
		Metadata: resource.GetMetadata(),
		Rules:    rules,
	}
}

func (a *adapter) adaptSGRule(ruleBlock *terraform2.Block) network2.SecurityGroupRule {

	rule := network2.SecurityGroupRule{
		Metadata:             ruleBlock.GetMetadata(),
		Outbound:             types2.BoolDefault(false, ruleBlock.GetMetadata()),
		Allow:                types2.BoolDefault(true, ruleBlock.GetMetadata()),
		SourceAddresses:      nil,
		SourcePorts:          nil,
		DestinationAddresses: nil,
		DestinationPorts:     nil,
		Protocol:             ruleBlock.GetAttribute("protocol").AsStringValueOrDefault("", ruleBlock),
	}

	accessAttr := ruleBlock.GetAttribute("access")
	if accessAttr.Equals("Allow") {
		rule.Allow = types2.Bool(true, accessAttr.GetMetadata())
	} else if accessAttr.Equals("Deny") {
		rule.Allow = types2.Bool(false, accessAttr.GetMetadata())
	}

	directionAttr := ruleBlock.GetAttribute("direction")
	if directionAttr.Equals("Inbound") {
		rule.Outbound = types2.Bool(false, directionAttr.GetMetadata())
	} else if directionAttr.Equals("Outbound") {
		rule.Outbound = types2.Bool(true, directionAttr.GetMetadata())
	}

	a.adaptSource(ruleBlock, &rule)
	a.adaptDestination(ruleBlock, &rule)

	return rule
}

func (a *adapter) adaptSource(ruleBlock *terraform2.Block, rule *network2.SecurityGroupRule) {
	if sourceAddressAttr := ruleBlock.GetAttribute("source_address_prefix"); sourceAddressAttr.IsString() {
		rule.SourceAddresses = append(rule.SourceAddresses, sourceAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if sourceAddressPrefixesAttr := ruleBlock.GetAttribute("source_address_prefixes"); sourceAddressPrefixesAttr.IsNotNil() {
		rule.SourceAddresses = append(rule.SourceAddresses, sourceAddressPrefixesAttr.AsStringValues()...)
	}

	if sourcePortRangesAttr := ruleBlock.GetAttribute("source_port_ranges"); sourcePortRangesAttr.IsNotNil() {
		ports := sourcePortRangesAttr.AsStringValues()
		for _, value := range ports {
			rule.SourcePorts = append(rule.SourcePorts, expandRange(value.Value(), value.GetMetadata()))
		}
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsString() {
		rule.SourcePorts = append(rule.SourcePorts, expandRange(sourcePortRangeAttr.Value().AsString(), sourcePortRangeAttr.GetMetadata()))
	} else if sourcePortRangeAttr := ruleBlock.GetAttribute("source_port_range"); sourcePortRangeAttr.IsNumber() {
		f := sourcePortRangeAttr.AsNumber()
		rule.SourcePorts = append(rule.SourcePorts, network2.PortRange{
			Metadata: sourcePortRangeAttr.GetMetadata(),
			Start:    int(f),
			End:      int(f),
		})
	}
}

func (a *adapter) adaptDestination(ruleBlock *terraform2.Block, rule *network2.SecurityGroupRule) {
	if destAddressAttr := ruleBlock.GetAttribute("destination_address_prefix"); destAddressAttr.IsString() {
		rule.DestinationAddresses = append(rule.DestinationAddresses, destAddressAttr.AsStringValueOrDefault("", ruleBlock))
	} else if destAddressPrefixesAttr := ruleBlock.GetAttribute("destination_address_prefixes"); destAddressPrefixesAttr.IsNotNil() {
		rule.DestinationAddresses = append(rule.DestinationAddresses, destAddressPrefixesAttr.AsStringValues()...)
	}

	if destPortRangesAttr := ruleBlock.GetAttribute("destination_port_ranges"); destPortRangesAttr.IsNotNil() {
		ports := destPortRangesAttr.AsStringValues()
		for _, value := range ports {
			rule.DestinationPorts = append(rule.DestinationPorts, expandRange(value.Value(), destPortRangesAttr.GetMetadata()))
		}
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsString() {
		rule.DestinationPorts = append(rule.DestinationPorts, expandRange(destPortRangeAttr.Value().AsString(), destPortRangeAttr.GetMetadata()))
	} else if destPortRangeAttr := ruleBlock.GetAttribute("destination_port_range"); destPortRangeAttr.IsNumber() {
		f := destPortRangeAttr.AsNumber()
		rule.DestinationPorts = append(rule.DestinationPorts, network2.PortRange{
			Metadata: destPortRangeAttr.GetMetadata(),
			Start:    int(f),
			End:      int(f),
		})
	}
}

func expandRange(r string, m types2.Metadata) network2.PortRange {
	start := 0
	end := 65535
	switch {
	case r == "*":
	case strings.Contains(r, "-"):
		if parts := strings.Split(r, "-"); len(parts) == 2 {
			if p1, err := strconv.ParseInt(parts[0], 10, 32); err == nil {
				start = int(p1)
			}
			if p2, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
				end = int(p2)
			}
		}
	default:
		if val, err := strconv.ParseInt(r, 10, 32); err == nil {
			start = int(val)
			end = int(val)
		}
	}

	return network2.PortRange{
		Metadata: m,
		Start:    start,
		End:      end,
	}
}

func adaptWatcherLog(resource *terraform2.Block) network2.NetworkWatcherFlowLog {
	flowLog := network2.NetworkWatcherFlowLog{
		Metadata: resource.GetMetadata(),
		RetentionPolicy: network2.RetentionPolicy{
			Metadata: resource.GetMetadata(),
			Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
			Days:     types2.IntDefault(0, resource.GetMetadata()),
		},
	}

	if retentionPolicyBlock := resource.GetBlock("retention_policy"); retentionPolicyBlock.IsNotNil() {
		flowLog.RetentionPolicy.Metadata = retentionPolicyBlock.GetMetadata()

		enabledAttr := retentionPolicyBlock.GetAttribute("enabled")
		flowLog.RetentionPolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, retentionPolicyBlock)

		daysAttr := retentionPolicyBlock.GetAttribute("days")
		flowLog.RetentionPolicy.Days = daysAttr.AsIntValueOrDefault(0, retentionPolicyBlock)
	}

	return flowLog
}
