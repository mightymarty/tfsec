package sqs

import (
	"github.com/liamg/iamgo"
	"github.com/mightymarty/tfsec/defsec/internal/adapters/terraform/aws/iam"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	iam2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	sqs2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/sqs"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"

	"github.com/google/uuid"
)

func Adapt(modules terraform2.Modules) sqs2.SQS {
	return sqs2.SQS{
		Queues: (&adapter{
			modules: modules,
			queues:  make(map[string]sqs2.Queue),
		}).adaptQueues(),
	}
}

type adapter struct {
	modules terraform2.Modules
	queues  map[string]sqs2.Queue
}

func (a *adapter) adaptQueues() []sqs2.Queue {
	for _, resource := range a.modules.GetResourcesByType("aws_sqs_queue") {
		a.adaptQueue(resource)
	}

	for _, policyBlock := range a.modules.GetResourcesByType("aws_sqs_queue_policy") {

		policy := iam2.Policy{
			Metadata: policyBlock.GetMetadata(),
			Name:     types2.StringDefault("", policyBlock.GetMetadata()),
			Document: iam2.Document{
				Metadata: policyBlock.GetMetadata(),
			},
		}
		if attr := policyBlock.GetAttribute("policy"); attr.IsString() {
			parsed, err := iamgo.ParseString(attr.Value().AsString())
			if err != nil {
				continue
			}
			policy.Document.Parsed = *parsed
			policy.Document.Metadata = attr.GetMetadata()
		} else if refBlock, err := a.modules.GetReferencedBlock(attr, policyBlock); err == nil {
			if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
				if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
					policy.Document.Parsed = doc.Document
					policy.Document.Metadata = doc.Source.GetMetadata()
				}
			}
		}

		if urlAttr := policyBlock.GetAttribute("queue_url"); urlAttr.IsNotNil() {
			if refBlock, err := a.modules.GetReferencedBlock(urlAttr, policyBlock); err == nil {
				if queue, ok := a.queues[refBlock.ID()]; ok {
					queue.Policies = append(queue.Policies, policy)
					a.queues[refBlock.ID()] = queue
					continue
				}
			}
		}

		a.queues[uuid.NewString()] = sqs2.Queue{
			Metadata: types2.NewUnmanagedMetadata(),
			Encryption: sqs2.Encryption{
				Metadata:          types2.NewUnmanagedMetadata(),
				ManagedEncryption: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				KMSKeyID:          types2.StringDefault("", types2.NewUnmanagedMetadata()),
			},
			Policies: []iam2.Policy{policy},
		}
	}

	var queues []sqs2.Queue
	for _, queue := range a.queues {
		queues = append(queues, queue)
	}
	return queues
}

func (a *adapter) adaptQueue(resource *terraform2.Block) {

	kmsKeyIdAttr := resource.GetAttribute("kms_master_key_id")
	kmsKeyIdVal := kmsKeyIdAttr.AsStringValueOrDefault("", resource)
	managedEncryption := resource.GetAttribute("sqs_managed_sse_enabled")

	var policies []iam2.Policy
	if attr := resource.GetAttribute("policy"); attr.IsString() {
		policy := iam2.Policy{
			Metadata: attr.GetMetadata(),
			Name:     types2.StringDefault("", attr.GetMetadata()),
			Document: iam2.Document{
				Metadata: attr.GetMetadata(),
			},
		}
		parsed, err := iamgo.ParseString(attr.Value().AsString())
		if err == nil {
			policy.Document.Parsed = *parsed
			policy.Document.Metadata = attr.GetMetadata()
			policy.Metadata = attr.GetMetadata()
			policies = append(policies, policy)
		}
	} else if refBlock, err := a.modules.GetReferencedBlock(attr, resource); err == nil {
		if refBlock.Type() == "data" && refBlock.TypeLabel() == "aws_iam_policy_document" {
			if doc, err := iam.ConvertTerraformDocument(a.modules, refBlock); err == nil {
				var policy iam2.Policy
				policy.Document.Parsed = doc.Document
				policy.Document.Metadata = doc.Source.GetMetadata()
				policies = append(policies, policy)
			}
		}
	}

	a.queues[resource.ID()] = sqs2.Queue{
		Metadata: resource.GetMetadata(),
		Encryption: sqs2.Encryption{
			Metadata:          resource.GetMetadata(),
			ManagedEncryption: managedEncryption.AsBoolValueOrDefault(false, resource),
			KMSKeyID:          kmsKeyIdVal,
		},
		Policies: policies,
	}
}
