package datalake

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	types.Metadata
	EnableEncryption types.BoolValue
}
