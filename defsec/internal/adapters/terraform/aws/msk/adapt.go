package msk

import (
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	msk2 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/msk"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) msk2.MSK {
	return msk2.MSK{
		Clusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform2.Modules) []msk2.Cluster {
	var clusters []msk2.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_msk_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform2.Block) msk2.Cluster {
	cluster := msk2.Cluster{
		Metadata: resource.GetMetadata(),
		EncryptionInTransit: msk2.EncryptionInTransit{
			Metadata:     resource.GetMetadata(),
			ClientBroker: types2.StringDefault("TLS_PLAINTEXT", resource.GetMetadata()),
		},
		Logging: msk2.Logging{
			Metadata: resource.GetMetadata(),
			Broker: msk2.BrokerLogging{
				Metadata: resource.GetMetadata(),
				S3: msk2.S3Logging{
					Metadata: resource.GetMetadata(),
					Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
				},
				Cloudwatch: msk2.CloudwatchLogging{
					Metadata: resource.GetMetadata(),
					Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
				},
				Firehose: msk2.FirehoseLogging{
					Metadata: resource.GetMetadata(),
					Enabled:  types2.BoolDefault(false, resource.GetMetadata()),
				},
			},
		},
	}

	if encryptBlock := resource.GetBlock("encryption_info"); encryptBlock.IsNotNil() {
		if encryptionInTransitBlock := encryptBlock.GetBlock("encryption_in_transit"); encryptionInTransitBlock.IsNotNil() {
			cluster.EncryptionInTransit.Metadata = encryptionInTransitBlock.GetMetadata()
			if clientBrokerAttr := encryptionInTransitBlock.GetAttribute("client_broker"); clientBrokerAttr.IsNotNil() {
				cluster.EncryptionInTransit.ClientBroker = clientBrokerAttr.AsStringValueOrDefault("TLS", encryptionInTransitBlock)
			}
		}
	}

	if logBlock := resource.GetBlock("logging_info"); logBlock.IsNotNil() {
		cluster.Logging.Metadata = logBlock.GetMetadata()
		if brokerLogsBlock := logBlock.GetBlock("broker_logs"); brokerLogsBlock.IsNotNil() {
			cluster.Logging.Broker.Metadata = brokerLogsBlock.GetMetadata()
			if brokerLogsBlock.HasChild("s3") {
				if s3Block := brokerLogsBlock.GetBlock("s3"); s3Block.IsNotNil() {
					s3enabledAttr := s3Block.GetAttribute("enabled")
					cluster.Logging.Broker.S3.Metadata = s3Block.GetMetadata()
					cluster.Logging.Broker.S3.Enabled = s3enabledAttr.AsBoolValueOrDefault(false, s3Block)
				}
			}
			if cloudwatchBlock := brokerLogsBlock.GetBlock("cloudwatch_logs"); cloudwatchBlock.IsNotNil() {
				cwEnabledAttr := cloudwatchBlock.GetAttribute("enabled")
				cluster.Logging.Broker.Cloudwatch.Metadata = cloudwatchBlock.GetMetadata()
				cluster.Logging.Broker.Cloudwatch.Enabled = cwEnabledAttr.AsBoolValueOrDefault(false, cloudwatchBlock)
			}
			if firehoseBlock := brokerLogsBlock.GetBlock("firehose"); firehoseBlock.IsNotNil() {
				firehoseEnabledAttr := firehoseBlock.GetAttribute("enabled")
				cluster.Logging.Broker.Firehose.Metadata = firehoseBlock.GetMetadata()
				cluster.Logging.Broker.Firehose.Enabled = firehoseEnabledAttr.AsBoolValueOrDefault(false, firehoseBlock)
			}
		}
	}

	return cluster
}
