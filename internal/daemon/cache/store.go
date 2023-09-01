// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

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

type Store struct {
	conn *db.DB
}

func Open(ctx context.Context, opt ...Option) (*Store, error) {
	const op = "cache.Open"
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
	underlying, err := db.Open(ctx, db.Sqlite, url)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	s := &Store{conn: underlying}
	s.conn.Debug(opts.withDebug)

	switch {
	case opts.withDbType == dbw.Sqlite:
		if err := s.createTables(ctx); err != nil {
			errors.Wrap(ctx, err, op)
		}
	default:
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("%q is not a supported cache store type", opts.withDbType))
	}
	return s, nil
}

func (s *Store) createTables(ctx context.Context) error {
	const op = "cache.(Store).createTables"
	rw := db.New(s.conn)
	if _, err := rw.Exec(ctx, cacheSchema, nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}
