// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package util

// Map maps a slice of one type into a slice of another using the provided map
// function
func Map[T, U any](in []T, f func(T) U) []U {
	var ret []U
	for _, t := range in {
		ret = append(ret, f(t))
	}
	return ret
}
