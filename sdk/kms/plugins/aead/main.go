package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-hclog"
	aead "github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2"
)

func main() {
	if err := aead.ServePlugin(aead.WithLogger(hclog.NewNullLogger())); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
