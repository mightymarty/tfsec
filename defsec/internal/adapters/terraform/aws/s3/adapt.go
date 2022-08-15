package s3

import (
	s32 "github.com/mightymarty/tfsec/defsec/pkg/providers/aws/s3"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) s32.S3 {

	a := &adapter{
		modules:   modules,
		bucketMap: make(map[string]*s32.Bucket),
	}

	return s32.S3{
		Buckets: a.adaptBuckets(),
	}
}
