// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package common

import (
	"database/sql"

	_ "github.com/jackc/pgx/v5"
)

func SqlOpen(driverName, dataSourceName string) (*sql.DB, error) {
	switch driverName {
	case "postgres", "pgx":
		driverName = "pgx"
	}
	return sql.Open(driverName, dataSourceName)
}
