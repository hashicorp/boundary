// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"os"
)

func main() {
	if err := serve(); err != nil {
		fmt.Println("Error serving plugin", err)
		os.Exit(1)
	}
	os.Exit(0)
}
