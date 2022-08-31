package tfsec

import (
	"github.com/mightymarty/tfsec/internal/app/tfsec/cmd"
)

func ScanWrapper(path string) (interface{}, error) {
	return cmd.RunTFScan(path)
}
