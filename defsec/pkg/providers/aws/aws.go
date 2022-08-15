package aws

import (
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/apigateway"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/athena"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudfront"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudtrail"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/cloudwatch"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/codebuild"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/config"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/documentdb"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/dynamodb"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ec2"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ecr"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ecs"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/efs"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/eks"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elasticache"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elasticsearch"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/elb"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/emr"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/iam"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/kinesis"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/kms"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/lambda"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/mq"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/msk"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/neptune"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/rds"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/redshift"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/s3"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/sam"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/sns"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/sqs"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/ssm"
	"github.com/mightymarty/tfsec/defsec/pkg/providers/aws/workspaces"
)

type AWS struct {
	APIGateway    apigateway.APIGateway
	Athena        athena.Athena
	Cloudfront    cloudfront.Cloudfront
	CloudTrail    cloudtrail.CloudTrail
	CloudWatch    cloudwatch.CloudWatch
	CodeBuild     codebuild.CodeBuild
	Config        config.Config
	DocumentDB    documentdb.DocumentDB
	DynamoDB      dynamodb.DynamoDB
	EC2           ec2.EC2
	ECR           ecr.ECR
	ECS           ecs.ECS
	EFS           efs.EFS
	EKS           eks.EKS
	ElastiCache   elasticache.ElastiCache
	Elasticsearch elasticsearch.Elasticsearch
	ELB           elb.ELB
	EMR           emr.EMR
	IAM           iam.IAM
	Kinesis       kinesis.Kinesis
	KMS           kms.KMS
	Lambda        lambda.Lambda
	MQ            mq.MQ
	MSK           msk.MSK
	Neptune       neptune.Neptune
	RDS           rds.RDS
	Redshift      redshift.Redshift
	SAM           sam.SAM
	S3            s3.S3
	SNS           sns.SNS
	SQS           sqs.SQS
	SSM           ssm.SSM
	WorkSpaces    workspaces.WorkSpaces
}
