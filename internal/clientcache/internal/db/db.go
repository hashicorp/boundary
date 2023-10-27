// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
)

//go:embed schema.sql
var cacheSchema string

// DefaultStoreUrl uses a temp in-memory sqlite database see: https://www.sqlite.org/inmemorydb.html
const DefaultStoreUrl = "file::memory:?_pragma=foreign_keys(1)"

// Open creates a database connection. WithUrl is supported, but by default it
// uses an in memory sqlite table. Sqlite is the only supported dbtype.
func Open(ctx context.Context, opt ...Option) (*db.DB, error) {
	const op = "db.Open"
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var url string
	switch {
	case opts.withUrl != "":
		url = opts.withUrl
	default:
		url = DefaultStoreUrl
	}
	// sqlite db must be set to 1 max open connection so requests can be serialized
	// otherwise reading while a tx is ongoing results in sql logic errors.
	conn, err := db.Open(ctx, db.Sqlite, url, db.WithMaxOpenConnections(1))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	conn.Debug(opts.withDebug)

	switch {
	case opts.withDbType == dbw.Sqlite:
		if err := createTables(ctx, conn); err != nil {
			errors.Wrap(ctx, err, op)
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q is not a supported cache store type", opts.withDbType))
	}
	return conn, nil
}

func createTables(ctx context.Context, conn *db.DB) error {
	const op = "db.createTables"
	rw := db.New(conn)
	if _, err := rw.Exec(ctx, cacheSchema, nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
