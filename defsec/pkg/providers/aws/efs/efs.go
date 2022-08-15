package efs

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	types.Metadata
	Encrypted types.BoolValue
}
