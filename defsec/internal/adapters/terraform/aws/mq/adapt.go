package mq

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	mq2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/mq"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) mq2.MQ {
	return mq2.MQ{
		Brokers: adaptBrokers(modules),
	}
}

func adaptBrokers(modules terraform2.Modules) []mq2.Broker {
	var brokers []mq2.Broker
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_mq_broker") {
			brokers = append(brokers, adaptBroker(resource))
		}
	}
	return brokers
}

func adaptBroker(resource *terraform2.Block) mq2.Broker {

	broker := mq2.Broker{
		Metadata:     resource.GetMetadata(),
		PublicAccess: types.BoolDefault(false, resource.GetMetadata()),
		Logging: mq2.Logging{
			Metadata: resource.GetMetadata(),
			General:  types.BoolDefault(false, resource.GetMetadata()),
			Audit:    types.BoolDefault(false, resource.GetMetadata()),
		},
	}

	publicAccessAttr := resource.GetAttribute("publicly_accessible")
	broker.PublicAccess = publicAccessAttr.AsBoolValueOrDefault(false, resource)
	if logsBlock := resource.GetBlock("logs"); logsBlock.IsNotNil() {
		broker.Logging.Metadata = logsBlock.GetMetadata()
		auditAttr := logsBlock.GetAttribute("audit")
		broker.Logging.Audit = auditAttr.AsBoolValueOrDefault(false, logsBlock)
		generalAttr := logsBlock.GetAttribute("general")
		broker.Logging.General = generalAttr.AsBoolValueOrDefault(false, logsBlock)
	}

	return broker
}
