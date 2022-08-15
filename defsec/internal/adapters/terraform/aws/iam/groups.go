package iam

import (
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptGroups(modules terraform2.Modules) []iam2.Group {

	groupMap, policyMap := mapGroups(modules)

	for _, policyBlock := range modules.GetResourcesByType("aws_iam_group_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		groupAttr := policyBlock.GetAttribute("group")
		if groupAttr.IsNil() {
			continue
		}
		groupBlock, err := modules.GetReferencedBlock(groupAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		group := groupMap[groupBlock.ID()]
		group.Policies = append(group.Policies, policy)
		groupMap[groupBlock.ID()] = group
	}

	for _, attachBlock := range modules.GetResourcesByType("aws_iam_group_policy_attachment") {
		if _, ok := policyMap[attachBlock.ID()]; ok {
			continue
		}
		groupAttr := attachBlock.GetAttribute("group")
		if groupAttr.IsNil() {
			continue
		}
		groupBlock, err := modules.GetReferencedBlock(groupAttr, attachBlock)
		if err != nil {
			continue
		}
		policyAttr := attachBlock.GetAttribute("policy_arn")
		if policyAttr.IsNil() {
			continue
		}
		policyBlock, err := modules.GetReferencedBlock(policyAttr, attachBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		group := groupMap[groupBlock.ID()]
		group.Policies = append(group.Policies, policy)
		groupMap[groupBlock.ID()] = group
	}

	var output []iam2.Group
	for _, group := range groupMap {
		output = append(output, group)
	}
	return output
}

func mapGroups(modules terraform2.Modules) (map[string]iam2.Group, map[string]struct{}) {
	groupMap := make(map[string]iam2.Group)
	policyMap := make(map[string]struct{})
	for _, groupBlock := range modules.GetResourcesByType("aws_iam_group") {
		var group iam2.Group
		group.Metadata = groupBlock.GetMetadata()
		group.Name = groupBlock.GetAttribute("name").AsStringValueOrDefault("", groupBlock)

		for _, block := range modules.GetResourcesByType("aws_iam_group_policy") {
			if !sameProvider(groupBlock, block) {
				continue
			}
			if groupAttr := block.GetAttribute("group"); groupAttr.IsString() {
				if groupAttr.Equals(group.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					group.Policies = append(group.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_group_policy_attachment") {
			if !sameProvider(groupBlock, block) {
				continue
			}
			if groupAttr := block.GetAttribute("group"); groupAttr.IsString() {
				if groupAttr.Equals(group.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					group.Policies = append(group.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		groupMap[groupBlock.ID()] = group
	}
	return groupMap, policyMap
}
