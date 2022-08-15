package iam

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"strings"

	"github.com/liamg/iamgo"
)

func sameProvider(b1, b2 *terraform2.Block) bool {

	if b1.HasChild("provider") != b2.HasChild("provider") {
		return false
	}

	var provider1, provider2 string
	if providerAttr := b1.GetAttribute("provider"); providerAttr.IsString() {
		provider1 = providerAttr.Value().AsString()
	}
	if providerAttr := b2.GetAttribute("provider"); providerAttr.IsString() {
		provider2 = providerAttr.Value().AsString()
	}
	return strings.EqualFold(provider1, provider2)
}

func parsePolicy(policyBlock *terraform2.Block, modules terraform2.Modules) (iam2.Policy, error) {
	policy := iam2.Policy{
		Metadata: policyBlock.GetMetadata(),
		Name:     policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock),
		Document: iam2.Document{
			Metadata: types.NewUnmanagedMetadata(),
			Parsed:   iamgo.Document{},
			IsOffset: false,
			HasRefs:  false,
		},
	}
	var err error
	doc, err := ParsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
	if err != nil {
		return policy, err
	}
	policy.Document = *doc
	return policy, nil
}

func adaptPolicies(modules terraform2.Modules) (policies []iam2.Policy) {
	for _, policyBlock := range modules.GetResourcesByType("aws_iam_policy") {
		policy := iam2.Policy{
			Metadata: policyBlock.GetMetadata(),
			Name:     policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock),
			Document: iam2.Document{
				Metadata: types.NewUnmanagedMetadata(),
				Parsed:   iamgo.Document{},
				IsOffset: false,
				HasRefs:  false,
			},
		}
		doc, err := ParsePolicyFromAttr(policyBlock.GetAttribute("policy"), policyBlock, modules)
		if err != nil {
			continue
		}
		policy.Document = *doc
		policies = append(policies, policy)
	}
	return
}
