package iam

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func ParsePolicyBlock(block *terraform2.Block) []iam2.Binding {
	var bindings []iam2.Binding
	for _, bindingBlock := range block.GetBlocks("binding") {
		binding := iam2.Binding{
			Metadata:                      bindingBlock.GetMetadata(),
			Members:                       nil,
			Role:                          bindingBlock.GetAttribute("role").AsStringValueOrDefault("", bindingBlock),
			IncludesDefaultServiceAccount: types2.BoolDefault(false, bindingBlock.GetMetadata()),
		}
		membersAttr := bindingBlock.GetAttribute("members")
		members := membersAttr.AsStringValues().AsStrings()
		for _, member := range members {
			binding.Members = append(binding.Members, types2.String(member, membersAttr.GetMetadata()))
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
