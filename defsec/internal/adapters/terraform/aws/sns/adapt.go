package sns

import (
	sns2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/sns"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) sns2.SNS {
	return sns2.SNS{
		Topics: adaptTopics(modules),
	}
}

func adaptTopics(modules terraform2.Modules) []sns2.Topic {
	var topics []sns2.Topic
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_sns_topic") {
			topics = append(topics, adaptTopic(resource))
		}
	}
	return topics
}

func adaptTopic(resourceBlock *terraform2.Block) sns2.Topic {
	return sns2.Topic{
		Metadata:   resourceBlock.GetMetadata(),
		Encryption: adaptEncryption(resourceBlock),
	}
}

func adaptEncryption(resourceBlock *terraform2.Block) sns2.Encryption {
	return sns2.Encryption{
		Metadata: resourceBlock.GetMetadata(),
		KMSKeyID: resourceBlock.GetAttribute("kms_master_key_id").AsStringValueOrDefault("", resourceBlock),
	}
}
