// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package util

// Pointer is just a generic function to return a pointer of whatever type is
// given
func Pointer[T any](input T) *T {
	ret := input
	return &ret
}
