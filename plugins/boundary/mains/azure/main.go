// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"

	az "github.com/hashicorp/boundary-plugin-azure/plugin"
	hp "github.com/hashicorp/boundary/sdk/plugins"
)

func main() {
	if err := hp.ServePlugin(new(az.AzurePlugin)); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
