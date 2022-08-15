package ec2

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	ec22 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ec2"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

type naclAdapter struct {
	naclRuleIDs terraform2.ResourceIDResolutions
}

type sgAdapter struct {
	sgRuleIDs terraform2.ResourceIDResolutions
}

func adaptDefaultVPCs(modules terraform2.Modules) []ec22.DefaultVPC {
	var defaultVPCs []ec22.DefaultVPC
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_default_vpc") {
			defaultVPCs = append(defaultVPCs, ec22.DefaultVPC{
				Metadata: resource.GetMetadata(),
			})
		}
	}
	return defaultVPCs
}

func (a *sgAdapter) adaptSecurityGroups(modules terraform2.Modules) []ec22.SecurityGroup {
	var securityGroups []ec22.SecurityGroup
	for _, resource := range modules.GetResourcesByType("aws_security_group") {
		securityGroups = append(securityGroups, a.adaptSecurityGroup(resource, modules))
	}
	orphanResources := modules.GetResourceByIDs(a.sgRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := ec22.SecurityGroup{
			Metadata:     types2.NewUnmanagedMetadata(),
			Description:  types2.StringDefault("", types2.NewUnmanagedMetadata()),
			IngressRules: nil,
			EgressRules:  nil,
		}
		for _, sgRule := range orphanResources {
			if sgRule.GetAttribute("type").Equals("ingress") {
				orphanage.IngressRules = append(orphanage.IngressRules, adaptSGRule(sgRule, modules))
			} else if sgRule.GetAttribute("type").Equals("egress") {
				orphanage.EgressRules = append(orphanage.EgressRules, adaptSGRule(sgRule, modules))
			}
		}
		securityGroups = append(securityGroups, orphanage)
	}

	return securityGroups
}

func (a *naclAdapter) adaptNetworkACLs(modules terraform2.Modules) []ec22.NetworkACL {
	var networkACLs []ec22.NetworkACL
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_network_acl") {
			networkACLs = append(networkACLs, a.adaptNetworkACL(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.naclRuleIDs.Orphans()...)
	if len(orphanResources) > 0 {
		orphanage := ec22.NetworkACL{
			Metadata: types2.NewUnmanagedMetadata(),
			Rules:    nil,
		}
		for _, naclRule := range orphanResources {
			orphanage.Rules = append(orphanage.Rules, adaptNetworkACLRule(naclRule))
		}
		networkACLs = append(networkACLs, orphanage)
	}

	return networkACLs
}

func (a *sgAdapter) adaptSecurityGroup(resource *terraform2.Block, module terraform2.Modules) ec22.SecurityGroup {
	var ingressRules []ec22.SecurityGroupRule
	var egressRules []ec22.SecurityGroupRule

	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	ingressBlocks := resource.GetBlocks("ingress")
	for _, ingressBlock := range ingressBlocks {
		ingressRules = append(ingressRules, adaptSGRule(ingressBlock, module))
	}

	egressBlocks := resource.GetBlocks("egress")
	for _, egressBlock := range egressBlocks {
		egressRules = append(egressRules, adaptSGRule(egressBlock, module))
	}

	rulesBlocks := module.GetReferencingResources(resource, "aws_security_group_rule", "security_group_id")
	for _, ruleBlock := range rulesBlocks {
		a.sgRuleIDs.Resolve(ruleBlock.ID())
		if ruleBlock.GetAttribute("type").Equals("ingress") {
			ingressRules = append(ingressRules, adaptSGRule(ruleBlock, module))
		} else if ruleBlock.GetAttribute("type").Equals("egress") {
			egressRules = append(egressRules, adaptSGRule(ruleBlock, module))
		}
	}

	return ec22.SecurityGroup{
		Metadata:     resource.GetMetadata(),
		Description:  descriptionVal,
		IngressRules: ingressRules,
		EgressRules:  egressRules,
	}
}

func adaptSGRule(resource *terraform2.Block, modules terraform2.Modules) ec22.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	var cidrs []types2.StringValue

	cidrBlocks := resource.GetAttribute("cidr_blocks")
	ipv6cidrBlocks := resource.GetAttribute("ipv6_cidr_blocks")
	varBlocks := modules.GetBlocks().OfType("variable")

	for _, vb := range varBlocks {
		if cidrBlocks.IsNotNil() && cidrBlocks.ReferencesBlock(vb) {
			cidrBlocks = vb.GetAttribute("default")
		}
		if ipv6cidrBlocks.IsNotNil() && ipv6cidrBlocks.ReferencesBlock(vb) {
			ipv6cidrBlocks = vb.GetAttribute("default")
		}
	}

	if cidrBlocks.IsNotNil() {
		cidrs = cidrBlocks.AsStringValues()
	}

	if ipv6cidrBlocks.IsNotNil() {
		cidrs = append(cidrs, ipv6cidrBlocks.AsStringValues()...)
	}

	return ec22.SecurityGroupRule{
		Metadata:    resource.GetMetadata(),
		Description: ruleDescVal,
		CIDRs:       cidrs,
	}
}

func (a *naclAdapter) adaptNetworkACL(resource *terraform2.Block, module *terraform2.Module) ec22.NetworkACL {
	var networkRules []ec22.NetworkACLRule
	rulesBlocks := module.GetReferencingResources(resource, "aws_network_acl_rule", "network_acl_id")
	for _, ruleBlock := range rulesBlocks {
		a.naclRuleIDs.Resolve(ruleBlock.ID())
		networkRules = append(networkRules, adaptNetworkACLRule(ruleBlock))
	}
	return ec22.NetworkACL{
		Metadata: resource.GetMetadata(),
		Rules:    networkRules,
	}
}

func adaptNetworkACLRule(resource *terraform2.Block) ec22.NetworkACLRule {
	var cidrs []types2.StringValue

	typeVal := types2.StringDefault("ingress", resource.GetMetadata())

	egressAtrr := resource.GetAttribute("egress")
	if egressAtrr.IsTrue() {
		typeVal = types2.String("egress", egressAtrr.GetMetadata())
	} else if egressAtrr.IsNotNil() {
		typeVal = types2.String("ingress", egressAtrr.GetMetadata())
	}

	actionAttr := resource.GetAttribute("rule_action")
	actionVal := actionAttr.AsStringValueOrDefault("", resource)

	protocolAtrr := resource.GetAttribute("protocol")
	protocolVal := protocolAtrr.AsStringValueOrDefault("-1", resource)

	cidrAttr := resource.GetAttribute("cidr_block")
	if cidrAttr.IsNotNil() {
		cidrs = append(cidrs, cidrAttr.AsStringValueOrDefault("", resource))
	}
	ipv4cidrAttr := resource.GetAttribute("ipv6_cidr_block")
	if ipv4cidrAttr.IsNotNil() {
		cidrs = append(cidrs, ipv4cidrAttr.AsStringValueOrDefault("", resource))
	}

	return ec22.NetworkACLRule{
		Metadata: resource.GetMetadata(),
		Type:     typeVal,
		Action:   actionVal,
		Protocol: protocolVal,
		CIDRs:    cidrs,
	}
}
