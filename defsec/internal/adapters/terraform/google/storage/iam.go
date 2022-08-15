package storage

import (
	iam3 "github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/google/iam"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/iam"
)

type parentedBinding struct {
	blockID       string
	bucketID      string
	bucketBlockID string
	bindings      []iam2.Binding
}

type parentedMember struct {
	blockID       string
	bucketID      string
	bucketBlockID string
	member        iam2.Member
}

func (a *adapter) adaptBindings() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_storage_bucket_iam_policy") {
		var parented parentedBinding
		parented.blockID = iamBlock.ID()

		bucketAttr := iamBlock.GetAttribute("bucket")
		if bucketAttr.IsString() {
			parented.bucketID = bucketAttr.Value().AsString()
		}

		if refBlock, err := a.modules.GetReferencedBlock(bucketAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_storage_bucket" {
				parented.bucketBlockID = refBlock.ID()
			}
		}

		policyAttr := iamBlock.GetAttribute("policy_data")
		if policyAttr.IsNil() {
			continue
		}

		policyBlock, err := a.modules.GetReferencedBlock(policyAttr, iamBlock)
		if err != nil {
			continue
		}

		parented.bindings = iam3.ParsePolicyBlock(policyBlock)
		a.bindings = append(a.bindings, parented)
	}

	for _, iamBlock := range a.modules.GetResourcesByType("google_storage_bucket_iam_binding") {

		var parented parentedBinding
		parented.blockID = iamBlock.ID()
		parented.bindings = []iam2.Binding{iam3.AdaptBinding(iamBlock, a.modules)}

		bucketAttr := iamBlock.GetAttribute("bucket")
		if bucketAttr.IsString() {
			parented.bucketID = bucketAttr.Value().AsString()
		}

		if refBlock, err := a.modules.GetReferencedBlock(bucketAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_storage_bucket" {
				parented.bucketBlockID = refBlock.ID()
			}
		}

		a.bindings = append(a.bindings, parented)
	}
}

func (a *adapter) adaptMembers() {

	for _, iamBlock := range a.modules.GetResourcesByType("google_storage_bucket_iam_member") {

		var parented parentedMember
		parented.blockID = iamBlock.ID()
		parented.member = iam3.AdaptMember(iamBlock, a.modules)

		bucketAttr := iamBlock.GetAttribute("bucket")
		if bucketAttr.IsString() {
			parented.bucketID = bucketAttr.Value().AsString()
		}

		if refBlock, err := a.modules.GetReferencedBlock(bucketAttr, iamBlock); err == nil {
			if refBlock.TypeLabel() == "google_storage_bucket" {
				parented.bucketBlockID = refBlock.ID()
			}
		}

		a.members = append(a.members, parented)
	}

}
