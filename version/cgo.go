// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

//go:build cgo
// +build cgo

package version

func init() {
	CgoEnabled = true
}
