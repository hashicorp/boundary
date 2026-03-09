// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
