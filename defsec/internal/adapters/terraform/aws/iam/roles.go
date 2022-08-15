package iam

import (
	"github.com/liamg/iamgo"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptRoles(modules terraform2.Modules) []iam2.Role {

	roleMap, policyMap := mapRoles(modules)

	for _, policyBlock := range modules.GetResourcesByType("aws_iam_role_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		roleAttr := policyBlock.GetAttribute("role")
		if roleAttr.IsNil() {
			continue
		}
		roleBlock, err := modules.GetReferencedBlock(roleAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		role := roleMap[roleBlock.ID()]
		role.Policies = append(role.Policies, policy)
		roleMap[roleBlock.ID()] = role
	}

	var output []iam2.Role
	for _, role := range roleMap {
		output = append(output, role)
	}
	return output
}

func mapRoles(modules terraform2.Modules) (map[string]iam2.Role, map[string]struct{}) {
	policyMap := make(map[string]struct{})
	roleMap := make(map[string]iam2.Role)
	for _, roleBlock := range modules.GetResourcesByType("aws_iam_role") {
		role := iam2.Role{
			Metadata: roleBlock.GetMetadata(),
			Name:     roleBlock.GetAttribute("name").AsStringValueOrDefault("", roleBlock),
			Policies: nil,
		}
		if inlineBlock := roleBlock.GetBlock("inline_policy"); inlineBlock.IsNotNil() {
			policy := iam2.Policy{
				Metadata: inlineBlock.GetMetadata(),
				Name:     inlineBlock.GetAttribute("name").AsStringValueOrDefault("", inlineBlock),
				Document: iam2.Document{
					Metadata: types.NewUnmanagedMetadata(),
					Parsed:   iamgo.Document{},
					IsOffset: false,
					HasRefs:  false,
				},
			}
			doc, err := ParsePolicyFromAttr(inlineBlock.GetAttribute("policy"), inlineBlock, modules)
			if err != nil {
				continue
			}
			policy.Document = *doc
			role.Policies = append(role.Policies, policy)
		}

		for _, block := range modules.GetResourcesByType("aws_iam_role_policy") {
			if !sameProvider(roleBlock, block) {
				continue
			}
			if roleAttr := block.GetAttribute("role"); roleAttr.IsString() {
				if roleAttr.Equals(role.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					role.Policies = append(role.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_role_policy_attachment") {
			if !sameProvider(roleBlock, block) {
				continue
			}
			if roleAttr := block.GetAttribute("role"); roleAttr.IsString() {
				if roleAttr.Equals(role.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					role.Policies = append(role.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		roleMap[roleBlock.ID()] = role
	}

	return roleMap, policyMap

}
