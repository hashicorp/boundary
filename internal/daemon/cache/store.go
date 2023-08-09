// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cache

import (
	"context"
	"fmt"

	_ "github.com/glebarez/go-sqlite"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-dbw"
)

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
	if _, err := rw.Exec(ctx, createTables, nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

const (
	createTables = `	
begin;

create table if not exists cache_persona (
  boundary_addr text not null,
  token_name text not null,
  keyring_type text not null,
  auth_token_id text not null, -- Expected token id stored in the token name
  -- the timestamp has this default in order for the db to store fractional seconds. 
  last_accessed_time timestamp not null default (strftime('%Y-%m-%d %H:%M:%f','now')),
  primary key (boundary_addr, keyring_type, token_name)
);

create table if not exists cache_target (
  boundary_addr text not null,
  token_name text not null,
  keyring_type text not null,
  id text not null,
  name text,
  description text,
  address text,
  item text,
  foreign key (boundary_addr, keyring_type, token_name)
	references cache_persona(boundary_addr, keyring_type, token_name)
	on delete cascade,
  primary key (boundary_addr, keyring_type, token_name, id)
);

create table if not exists cache_api_error (
	token_name text not null,
	resource_type text not null,
	error text not null,
	create_time timestamp not null default current_timestamp,
	primary key (token_name, resource_type)
);

commit;
`
)
