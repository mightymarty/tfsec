package kms

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type KMS struct {
	Keys []Key
}

const (
	KeyUsageSignAndVerify = "SIGN_VERIFY"
)

type Key struct {
	types.Metadata
	Usage           types.StringValue
	RotationEnabled types.BoolValue
}
