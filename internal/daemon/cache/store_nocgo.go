// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !cgo
// +build !cgo

package cache

import (
	_ "github.com/glebarez/go-sqlite"
)
