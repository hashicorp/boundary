// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build amd64 || arm64

package db

import (
	"github.com/glebarez/sqlite"
	"github.com/hashicorp/go-dbw"
)

func init() {
	sqliteOpen = supportedSqlite
}

func supportedSqlite(s string) (dbw.Dialector, error) {
	return sqlite.Open(s), nil
}
