package tfsec

import (
	"fmt"
	"github.com/mightymarty/tfsec/internal/app/tfsec/cmd"
)

func ScanWrapper(path string) (string, error) {
	return cmd.RunTFScan(path)
}

func TestFuncCall() {
	fmt.Println("testing func calls")
}
