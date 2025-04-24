// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !netbsd
// +build !netbsd

package base

func init() {
	MinioEnabled = true
}
