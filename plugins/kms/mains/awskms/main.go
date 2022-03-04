package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
)

func main() {
	if err := gkwp.ServePlugin(awskms.NewWrapper(), gkwp.WithLogger(hclog.NewNullLogger())); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
