package iam

import (
	"github.com/google/uuid"
	"github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/iam"
)

// see https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_organization_iam

func (a *adapter) adaptOrganizationIAM() {
	a.adaptOrganizationMembers()
	a.adaptOrganizationBindings()
}

func (a *adapter) adaptOrganizationMembers() {
	for _, iamBlock := range a.modules.GetResourcesByType("google_organization_iam_member") {
		member := a.adaptMember(iamBlock)
		organizationAttr := iamBlock.GetAttribute("organization")
		if organizationAttr.IsNil() {
			organizationAttr = iamBlock.GetAttribute("org_id")
		}

		if refBlock, err := a.modules.GetReferencedBlock(organizationAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_organization" {
				a.addOrg(refBlock.ID())
				org := a.orgs[refBlock.ID()]
				org.Members = append(org.Members, member)
				a.orgs[refBlock.ID()] = org
				continue
			}
		}

		// we didn't find the organization - add an unmanaged one
		placeholderID := uuid.NewString()
		org := iam2.Organization{
			Metadata: types.NewUnmanagedMetadata(),
			Members:  []iam2.Member{member},
		}
		a.orgs[placeholderID] = org

	}
}

func (a *adapter) adaptOrganizationBindings() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_organization_iam_policy") {

		policyAttr := iamBlock.GetAttribute("policy_data")
		if policyAttr.IsNil() {
			continue
		}
		policyBlock, err := a.modules.GetReferencedBlock(policyAttr, iamBlock)
		if err != nil {
			continue
		}
		bindings := ParsePolicyBlock(policyBlock)
		orgAttr := iamBlock.GetAttribute("organization")

		if refBlock, err := a.modules.GetReferencedBlock(orgAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_organization" {
				if org, ok := a.orgs[refBlock.ID()]; ok {
					org.Bindings = append(org.Bindings, bindings...)
					a.orgs[refBlock.ID()] = org
					continue
				}
			}
		}

		// we didn't find the organization - add an unmanaged one
		placeholderID := uuid.NewString()
		org := iam2.Organization{
			Metadata: types.NewUnmanagedMetadata(),
			Bindings: bindings,
		}
		a.orgs[placeholderID] = org
	}

	for _, iamBlock := range a.modules.GetResourcesByType("google_organization_iam_binding") {
		binding := a.adaptBinding(iamBlock)
		organizationAttr := iamBlock.GetAttribute("organization")
		if organizationAttr.IsNil() {
			organizationAttr = iamBlock.GetAttribute("org_id")
		}

		if refBlock, err := a.modules.GetReferencedBlock(organizationAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_organization" {
				a.addOrg(refBlock.ID())
				org := a.orgs[refBlock.ID()]
				org.Bindings = append(org.Bindings, binding)
				a.orgs[refBlock.ID()] = org
				continue
			}
		}

		// we didn't find the organization - add an unmanaged one
		placeholderID := uuid.NewString()
		org := iam2.Organization{
			Metadata: types.NewUnmanagedMetadata(),
			Bindings: []iam2.Binding{binding},
		}
		a.orgs[placeholderID] = org
	}
}
