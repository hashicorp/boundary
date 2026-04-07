// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build !netbsd
// +build !netbsd

package base

func init() {
	MinioEnabled = true
}
