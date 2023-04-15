// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package test

import (
	"flag"
	"testing"
)

func init() {
	testing.Init()
	flag.Parse()
}

// IsTestRun will return whether or not we're operating within the context of a
// test.
func IsTestRun() bool {
	// TODO jimlambrt 4/23 -> convert to go 1.21 built-in func when it's
	// available in boundary:
	// https://github.com/golang/go/commit/7f38067acb738c43d870400dd648662d31456f5f#diff-b3e6126779b5ec9d3d6cea7cc54054ba78f4d7a0a6248d9e458bbd9b3d72fce3

	// just check if the test verbose (test.v) has been initialized... we don't
	// care about it's value.
	return flag.Lookup("test.v") != nil
}
