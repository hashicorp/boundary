// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"

	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/ibmkp/v2"
)

func main() {
	if err := gkwp.ServePlugin(ibmkp.NewWrapper()); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
