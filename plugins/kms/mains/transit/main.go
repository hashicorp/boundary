// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"

	gkwp "github.com/hashicorp/go-kms-wrapping/plugin/v2"
	"github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
)

func main() {
	if err := gkwp.ServePlugin(transit.NewWrapper()); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
