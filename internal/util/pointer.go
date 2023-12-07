// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package util

// Pointer is just a generic function to return a pointer of whatever type is
// given
func Pointer[T any](input T) *T {
	ret := input
	return &ret
}
