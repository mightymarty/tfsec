package iam

import (
	"github.com/google/uuid"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func adaptUsers(modules terraform2.Modules) []iam2.User {
	userMap, policyMap := mapUsers(modules)
	for _, policyBlock := range modules.GetResourcesByType("aws_iam_user_policy") {
		if _, ok := policyMap[policyBlock.ID()]; ok {
			continue
		}
		userAttr := policyBlock.GetAttribute("user")
		if userAttr.IsNil() {
			continue
		}
		userBlock, err := modules.GetReferencedBlock(userAttr, policyBlock)
		if err != nil {
			continue
		}
		policy, err := parsePolicy(policyBlock, modules)
		if err != nil {
			continue
		}
		user := userMap[userBlock.ID()]
		user.Policies = append(user.Policies, policy)
		userMap[userBlock.ID()] = user
	}
	for _, block := range modules.GetResourcesByType("aws_iam_access_key") {
		if userAttr := block.GetAttribute("user"); userAttr.IsString() {
			var found bool
			for _, user := range userMap {
				if user.Name.EqualTo(userAttr.Value().AsString()) {
					found = true
					break
				}
			}
			if found {
				continue
			}
			key, err := adaptAccessKey(block)
			if err != nil {
				continue
			}
			userMap[uuid.NewString()] = iam2.User{
				Metadata:   block.GetMetadata(),
				Name:       userAttr.AsStringValueOrDefault("", block),
				AccessKeys: []iam2.AccessKey{*key},
				LastAccess: types2.TimeUnresolvable(block.GetMetadata()),
			}
		}
	}

	var output []iam2.User
	for _, user := range userMap {
		output = append(output, user)
	}
	return output
}

// nolint
func mapUsers(modules terraform2.Modules) (map[string]iam2.User, map[string]struct{}) {
	userMap := make(map[string]iam2.User)
	policyMap := make(map[string]struct{})
	for _, userBlock := range modules.GetResourcesByType("aws_iam_user") {
		user := iam2.User{
			Metadata:   userBlock.GetMetadata(),
			Name:       userBlock.GetAttribute("name").AsStringValueOrDefault("", userBlock),
			LastAccess: types2.TimeUnresolvable(userBlock.GetMetadata()),
		}

		for _, block := range modules.GetResourcesByType("aws_iam_user_policy") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); userAttr.IsString() {
				if userAttr.Equals(user.Name.Value()) {
					policy, err := parsePolicy(block, modules)
					if err != nil {
						continue
					}
					user.Policies = append(user.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_user_policy_attachment") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); userAttr.IsString() {
				if userAttr.Equals(user.Name.Value()) {
					policyAttr := block.GetAttribute("policy_arn")

					policyBlock, err := modules.GetReferencedBlock(policyAttr, block)
					if err != nil {
						continue
					}
					policy, err := parsePolicy(policyBlock, modules)
					if err != nil {
						continue
					}
					user.Policies = append(user.Policies, policy)
					policyMap[block.ID()] = struct{}{}
				}
			}
		}

		for _, block := range modules.GetResourcesByType("aws_iam_access_key") {
			if !sameProvider(userBlock, block) {
				continue
			}
			if userAttr := block.GetAttribute("user"); (userAttr.IsString() && userAttr.Equals(user.Name.Value())) || userAttr.ReferencesBlock(userBlock) {
				key, err := adaptAccessKey(block)
				if err != nil {
					continue
				}
				user.AccessKeys = append(user.AccessKeys, *key)
			}
		}

		userMap[userBlock.ID()] = user
	}
	return userMap, policyMap

}

func adaptAccessKey(block *terraform2.Block) (*iam2.AccessKey, error) {

	active := types2.BoolDefault(true, block.GetMetadata())
	if activeAttr := block.GetAttribute("status"); activeAttr.IsString() {
		active = types2.Bool(activeAttr.Equals("Inactive"), activeAttr.GetMetadata())
	}

	key := iam2.AccessKey{
		Metadata:     block.GetMetadata(),
		AccessKeyId:  types2.StringUnresolvable(block.GetMetadata()),
		CreationDate: types2.TimeUnresolvable(block.GetMetadata()),
		LastAccess:   types2.TimeUnresolvable(block.GetMetadata()),
		Active:       active,
	}
	return &key, nil
}
