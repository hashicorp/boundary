package common

import (
	"database/sql"

	_ "github.com/jackc/pgx/v4"
)

func SqlOpen(driverName, dataSourceName string) (*sql.DB, error) {
	switch driverName {
	case "postgres", "pgx":
		driverName = "pgx"
	}
	return sql.Open(driverName, dataSourceName)
}
