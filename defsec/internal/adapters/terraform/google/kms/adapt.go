package kms

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
	kms2 "github.com/mightymarty/tfsec/defsec/pkg/providers/google/kms"
	terraform2 "github.com/mightymarty/tfsec/defsec/pkg/terraform"
	"strconv"
)

func Adapt(modules terraform2.Modules) kms2.KMS {
	return kms2.KMS{
		KeyRings: adaptKeyRings(modules),
	}
}

func adaptKeyRings(modules terraform2.Modules) []kms2.KeyRing {
	var keyRings []kms2.KeyRing
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_kms_key_ring") {
			var keys []kms2.Key

			keyBlocks := module.GetReferencingResources(resource, "google_kms_crypto_key", "key_ring")
			for _, keyBlock := range keyBlocks {
				keys = append(keys, adaptKey(keyBlock))
			}
			keyRings = append(keyRings, kms2.KeyRing{
				Metadata: resource.GetMetadata(),
				Keys:     keys,
			})
		}
	}
	return keyRings
}

func adaptKey(resource *terraform2.Block) kms2.Key {

	key := kms2.Key{
		Metadata:              resource.GetMetadata(),
		RotationPeriodSeconds: types.IntDefault(-1, resource.GetMetadata()),
	}

	rotationPeriodAttr := resource.GetAttribute("rotation_period")
	if !rotationPeriodAttr.IsString() {
		return key
	}
	rotationStr := rotationPeriodAttr.Value().AsString()
	if rotationStr[len(rotationStr)-1:] != "s" {
		return key
	}
	seconds, err := strconv.Atoi(rotationStr[:len(rotationStr)-1])
	if err != nil {
		return key
	}

	key.RotationPeriodSeconds = types.Int(seconds, rotationPeriodAttr.GetMetadata())
	return key
}
