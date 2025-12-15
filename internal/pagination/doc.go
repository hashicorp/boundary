// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package pagination implements generic functions for paginating
// through a collection using callbacks. The functions will automatically
// request additional items to match the input page size even when
// some items may be filtered out.
// See example_test.go for examples of using the library.
package pagination
