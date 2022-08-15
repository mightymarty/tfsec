package rds

import (
	"github.com/mightymarty/tfsec/defsec/internal/types"
)

type Classic struct {
	types.Metadata
	DBSecurityGroups []DBSecurityGroup
}

type DBSecurityGroup struct {
	types.Metadata
}
