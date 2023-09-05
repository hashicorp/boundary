// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

//go:build cgo
// +build cgo

package db

import (
	"github.com/hashicorp/go-dbw"
	"gorm.io/driver/sqlite"
)

func sqliteOpen(connectionUrl string) dbw.Dialector {
	return sqlite.Open(connectionUrl)
}
