// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package test

import (
	"flag"
	"os"
	"strings"
)

// IsTestRun will return whether or not we're operating within the context of a
// test.
func IsTestRun() bool {
	// TODO jimlambrt 4/23 -> convert to go 1.21 built-in func when it's
	// available in boundary:
	// https://github.com/golang/go/commit/7f38067acb738c43d870400dd648662d31456f5f#diff-b3e6126779b5ec9d3d6cea7cc54054ba78f4d7a0a6248d9e458bbd9b3d72fce3
	switch {
	case flag.Lookup("test.v") != nil:
		return true
	case strings.HasSuffix(os.Args[0], ".test"):
		return true
	case strings.Contains(os.Args[0], "/_test/"):
		return true
	default:
		return false
	}
}
