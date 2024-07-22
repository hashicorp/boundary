// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"

	google "github.com/hashicorp/boundary-plugin-google/plugin"
	hp "github.com/hashicorp/boundary/sdk/plugins"
)

func main() {
	if err := hp.ServePlugin(new(google.GooglePlugin)); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
