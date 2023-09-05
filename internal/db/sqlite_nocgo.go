// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build !cgo
// +build !cgo

package db

import (
	"github.com/glebarez/sqlite"
	"github.com/hashicorp/go-dbw"
)

func sqliteOpen(connectionUrl string) dbw.Dialector {
	return sqlite.Open(connectionUrl)
}
