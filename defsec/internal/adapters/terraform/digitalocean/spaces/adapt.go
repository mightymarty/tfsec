package spaces

import (
	"github.com/google/uuid"
	types2 "github.com/mightymarty/tfsec/defsec/internal/types"
	spaces2 "github.com/mightymarty/tfsec/defsec/pkg/providers/digitalocean/spaces"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
)

func Adapt(modules terraform2.Modules) spaces2.Spaces {
	return spaces2.Spaces{
		Buckets: adaptBuckets(modules),
	}
}

func adaptBuckets(modules terraform2.Modules) []spaces2.Bucket {
	bucketMap := make(map[string]spaces2.Bucket)
	for _, module := range modules {

		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket") {

			bucket := spaces2.Bucket{
				Metadata:     block.GetMetadata(),
				Name:         block.GetAttribute("name").AsStringValueOrDefault("", block),
				Objects:      nil,
				ACL:          block.GetAttribute("acl").AsStringValueOrDefault("public-read", block),
				ForceDestroy: block.GetAttribute("force_destroy").AsBoolValueOrDefault(false, block),
				Versioning: spaces2.Versioning{
					Metadata: block.GetMetadata(),
					Enabled:  types2.BoolDefault(false, block.GetMetadata()),
				},
			}

			if versioning := block.GetBlock("versioning"); versioning.IsNotNil() {
				bucket.Versioning = spaces2.Versioning{
					Metadata: versioning.GetMetadata(),
					Enabled:  versioning.GetAttribute("enabled").AsBoolValueOrDefault(false, versioning),
				}
			}
			bucketMap[block.ID()] = bucket
		}
		for _, block := range module.GetResourcesByType("digitalocean_spaces_bucket_object") {
			object := spaces2.Object{
				Metadata: block.GetMetadata(),
				ACL:      block.GetAttribute("acl").AsStringValueOrDefault("private", block),
			}
			bucketName := block.GetAttribute("bucket")
			var found bool
			if bucketName.IsString() {
				for i, bucket := range bucketMap {
					if bucket.Name.Value() == bucketName.Value().AsString() {
						bucket.Objects = append(bucket.Objects, object)
						bucketMap[i] = bucket
						found = true
						break
					}
				}
				if found {
					continue
				}
			} else if bucketName.IsNotNil() {
				if referencedBlock, err := module.GetReferencedBlock(bucketName, block); err == nil {
					if bucket, ok := bucketMap[referencedBlock.ID()]; ok {
						bucket.Objects = append(bucket.Objects, object)
						bucketMap[referencedBlock.ID()] = bucket
						continue
					}
				}
			}
			bucketMap[uuid.NewString()] = spaces2.Bucket{
				Metadata: types2.NewUnmanagedMetadata(),
				Name:     types2.StringDefault("", types2.NewUnmanagedMetadata()),
				Objects: []spaces2.Object{
					object,
				},
				ACL:          types2.StringDefault("private", types2.NewUnmanagedMetadata()),
				ForceDestroy: types2.BoolDefault(false, types2.NewUnmanagedMetadata()),
				Versioning: spaces2.Versioning{
					Metadata: block.GetMetadata(),
					Enabled:  types2.BoolDefault(false, block.GetMetadata()),
				},
			}
		}
	}

	var buckets []spaces2.Bucket
	for _, bucket := range bucketMap {
		buckets = append(buckets, bucket)
	}
	return buckets
}
