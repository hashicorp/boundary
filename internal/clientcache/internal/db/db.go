// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/go-dbw"
)

//go:embed schema.sql
var cacheSchema string

//go:embed schema_reset.sql
var cacheSchemaReset string

// DefaultStoreUrl uses a temp in-memory sqlite database see: https://www.sqlite.org/inmemorydb.html
const DefaultStoreUrl = "file::memory:?_pragma=foreign_keys(1)"

// Open creates a database connection. WithUrl is supported, but by default it
// uses an in memory sqlite table. Sqlite is the only supported dbtype.
// Supported options: WithUrl, WithGormFormatter, WithDebug,
// WithTestValidSchemaVersion (for testing purposes)
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

	dbOpts := []db.Option{db.WithMaxOpenConnections(1)}
	if !util.IsNil(opts.withGormFormatter) {
		dbOpts = append(dbOpts, db.WithGormFormatter(opts.withGormFormatter))
	}

	// sqlite db must be set to 1 max open connection so requests can be serialized
	// otherwise reading while a tx is ongoing results in sql logic errors.
	conn, err := db.Open(ctx, db.Sqlite, url, dbOpts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	defer func() {
		// let's not capture the output of resetSchema and createTables, so
		// we'll defer turning on debug
		conn.Debug(opts.withDebug)
	}()
	switch {
	case opts.withDbType == dbw.Sqlite && url == DefaultStoreUrl:
		if err := createTables(ctx, conn); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	case opts.withDbType == dbw.Sqlite && url != DefaultStoreUrl:
		ok, err := validSchema(ctx, conn, opt...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if !ok || opts.withForceResetSchema {
			if err := resetSchema(ctx, conn); err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			if err := createTables(ctx, conn); err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q is not a supported cache store type", opts.withDbType))
	}
	return conn, nil
}

func resetSchema(ctx context.Context, conn *db.DB) error {
	const op = "db.resetSchema"
	rw := db.New(conn)
	if _, err := rw.Exec(ctx, cacheSchemaReset, nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

func createTables(ctx context.Context, conn *db.DB) error {
	const op = "db.createTables"
	rw := db.New(conn)
	if _, err := rw.Exec(ctx, cacheSchema, nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// validSchema checks of the schema is valid based on its version. Options
// supported: withTestValidSchemaVersion (for testing purposes)
func validSchema(ctx context.Context, conn *db.DB, opt ...Option) (bool, error) {
	const op = "validateSchema"
	switch {
	case conn == nil:
		return false, errors.New(ctx, errors.InvalidParameter, op, "conn is missing")
	}
	opts, err := getOpts(opt...)
	if err != nil {
		return false, errors.Wrap(ctx, err, op)
	}
	if opts.withSchemaVersion == "" {
		opts.withSchemaVersion = schemaCurrentVersion
	}

	rw := db.New(conn)
	s := schema{}
	err = rw.LookupWhere(ctx, &s, "1=1", nil)
	switch {
	case err != nil && strings.Contains(err.Error(), "no such table: schema_version"):
		return false, nil
	case err != nil:
		// not sure if we should return the error or just return false so the
		// schema is recreated... for now return the error.
		return false, fmt.Errorf("%s: unable to get version: %w", op, err)
	case s.Version != opts.withSchemaVersion:
		return false, nil
	default:
		return true, nil
	}
}

// schema represents the current schema in the database
type schema struct {
	// Version of the schema
	Version string
	// UpdateTime is the last update of the version
	UpdateTime time.Time
	// CreateTime is the create time of the initial version
	CreateTime time.Time
}

const (
	schemaTableName      = "schema_version"
	schemaCurrentVersion = "v0.0.3"
)

// TableName returns the table name
func (s *schema) TableName() string {
	return schemaTableName
}
