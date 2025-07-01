// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"context"
	"database/sql"
)

// Reader interface defines lookups/searching for resources
type Reader interface {
	// LookupBy will lookup a resource by it's primary keys, which must be
	// unique. If the resource implements either ResourcePublicIder or
	// ResourcePrivateIder interface, then they are used as the resource's
	// primary key for lookup.  Otherwise, the resource tags are used to
	// determine it's primary key(s) for lookup.
	LookupBy(ctx context.Context, resource interface{}, opt ...Option) error

	// LookupByPublicId will lookup resource by its public_id which must be unique.
	LookupByPublicId(ctx context.Context, resource ResourcePublicIder, opt ...Option) error

	// LookupWhere will lookup and return the first resource using a where clause with parameters
	LookupWhere(ctx context.Context, resource interface{}, where string, args []interface{}, opt ...Option) error

	// SearchWhere will search for all the resources it can find using a where
	// clause with parameters. Supports the WithLimit option.  If
	// WithLimit < 0, then unlimited results are returned.  If WithLimit == 0, then
	// default limits are used for results.
	SearchWhere(ctx context.Context, resources interface{}, where string, args []interface{}, opt ...Option) error

	// Query will run the raw query and return the *sql.Rows results. Query will
	// operate within the context of any ongoing transaction for the dbw.Reader.  The
	// caller must close the returned *sql.Rows. Query can/should be used in
	// combination with ScanRows.
	Query(ctx context.Context, sql string, values []interface{}, opt ...Option) (*sql.Rows, error)

	// ScanRows will scan sql rows into the interface provided
	ScanRows(rows *sql.Rows, result interface{}) error

	// Dialect returns the dialect and raw connection name of the underlying database.
	Dialect() (_ DbType, rawName string, _ error)
}

// ResourcePublicIder defines an interface that LookupByPublicId() and
// LookupBy() can use to get the resource's public id.
type ResourcePublicIder interface {
	GetPublicId() string
}

// ResourcePrivateIder defines an interface that LookupBy() can use to get the
// resource's private id.
type ResourcePrivateIder interface {
	GetPrivateId() string
}
