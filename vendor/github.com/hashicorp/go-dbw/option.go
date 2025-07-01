// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbw

import (
	"github.com/hashicorp/go-hclog"
)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*Options)

// Options - how Options are represented which have been set via an Option
// function.  Use GetOpts(...) to populated this struct with the options that
// have been specified for an operation.  All option fields are exported so
// they're available for use by other packages.
type Options struct {
	// WithBeforeWrite provides and option to provide a func to be called before a
	// write operation. The i interface{} passed at runtime will be the resource(s)
	// being written.
	WithBeforeWrite func(i interface{}) error

	// WithAfterWrite provides and option to provide a func to be called after a
	// write operation.  The i interface{} passed at runtime will be the resource(s)
	// being written.
	WithAfterWrite func(i interface{}, rowsAffected int) error

	// WithLookup enables a lookup after a write operation.
	WithLookup bool

	// WithLimit provides an option to provide a limit.  Intentionally allowing
	// negative integers.   If WithLimit < 0, then unlimited results are returned.
	// If WithLimit == 0, then default limits are used for results (see DefaultLimit
	// const).
	WithLimit int

	// WithFieldMaskPaths provides an option to provide field mask paths for update
	// operations.
	WithFieldMaskPaths []string

	// WithNullPaths provides an option to provide null paths for update
	// operations.
	WithNullPaths []string

	// WithVersion provides an option version number for update operations.  Using
	// this option requires that your resource has a version column that's
	// incremented for every successful update operation.  Version provides an
	// optimistic locking mechanism for write operations.
	WithVersion *uint32

	WithSkipVetForWrite bool

	// WithWhereClause provides an option to provide a where clause for an
	// operation.
	WithWhereClause string

	// WithWhereClauseArgs provides an option to provide a where clause arguments for an
	// operation.
	WithWhereClauseArgs []interface{}

	// WithOrder provides an option to provide an order when searching and looking
	// up.
	WithOrder string

	// WithPrngValues provides an option to provide values to seed an PRNG when generating IDs
	WithPrngValues []string

	// WithLogger specifies an optional hclog to use for db operations.  It's only
	// valid for Open(..) and OpenWith(...) The logger provided can optionally
	// implement the LogWriter interface as well which would override the default
	// behavior for a logger (the default only emits postgres errors)
	WithLogger hclog.Logger

	// WithMinOpenConnections specifies and optional min open connections for the
	// database.  A value of zero means that there is no min.
	WithMaxOpenConnections int

	// WithMaxOpenConnections specifies and optional max open connections for the
	// database.  A value of zero equals unlimited connections
	WithMinOpenConnections int

	// WithDebug indicates that the given operation should invoke debug output
	// mode
	WithDebug bool

	// WithOnConflict specifies an optional on conflict criteria which specify
	// alternative actions to take when an insert results in a unique constraint or
	// exclusion constraint error
	WithOnConflict *OnConflict

	// WithRowsAffected specifies an option for returning the rows affected
	// and typically used with "bulk" write operations.
	WithRowsAffected *int64

	// WithTable specifies an option for setting a table name to use for the
	// operation.
	WithTable string

	// WithBatchSize specifies an option for setting the batch size for bulk
	// operations. If WithBatchSize == 0, then the default batch size is used.
	WithBatchSize int

	withLogLevel LogLevel
}

func getDefaultOptions() Options {
	return Options{
		WithFieldMaskPaths: []string{},
		WithNullPaths:      []string{},
		WithBatchSize:      DefaultBatchSize,
		withLogLevel:       Error,
	}
}

// WithBeforeWrite provides and option to provide a func to be called before a
// write operation. The i interface{} passed at runtime will be the resource(s)
// being written.
func WithBeforeWrite(fn func(i interface{}) error) Option {
	return func(o *Options) {
		o.WithBeforeWrite = fn
	}
}

// WithAfterWrite provides and option to provide a func to be called after a
// write operation.  The i interface{} passed at runtime will be the resource(s)
// being written.
func WithAfterWrite(fn func(i interface{}, rowsAffected int) error) Option {
	return func(o *Options) {
		o.WithAfterWrite = fn
	}
}

// WithLookup enables a lookup after a write operation.
func WithLookup(enable bool) Option {
	return func(o *Options) {
		o.WithLookup = enable
	}
}

// WithFieldMaskPaths provides an option to provide field mask paths for update
// operations.
func WithFieldMaskPaths(paths []string) Option {
	return func(o *Options) {
		o.WithFieldMaskPaths = paths
	}
}

// WithNullPaths provides an option to provide null paths for update operations.
func WithNullPaths(paths []string) Option {
	return func(o *Options) {
		o.WithNullPaths = paths
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results (see DefaultLimit
// const).
func WithLimit(limit int) Option {
	return func(o *Options) {
		o.WithLimit = limit
	}
}

// WithVersion provides an option version number for update operations.  Using
// this option requires that your resource has a version column that's
// incremented for every successful update operation.  Version provides an
// optimistic locking mechanism for write operations.
func WithVersion(version *uint32) Option {
	return func(o *Options) {
		o.WithVersion = version
	}
}

// WithSkipVetForWrite provides an option to allow skipping vet checks to allow
// testing lower-level SQL triggers and constraints
func WithSkipVetForWrite(enable bool) Option {
	return func(o *Options) {
		o.WithSkipVetForWrite = enable
	}
}

// WithWhere provides an option to provide a where clause with arguments for an
// operation.
func WithWhere(whereClause string, args ...interface{}) Option {
	return func(o *Options) {
		o.WithWhereClause = whereClause
		o.WithWhereClauseArgs = append(o.WithWhereClauseArgs, args...)
	}
}

// WithOrder provides an option to provide an order when searching and looking
// up.
func WithOrder(withOrder string) Option {
	return func(o *Options) {
		o.WithOrder = withOrder
	}
}

// WithPrngValues provides an option to provide values to seed an PRNG when generating IDs
func WithPrngValues(withPrngValues []string) Option {
	return func(o *Options) {
		o.WithPrngValues = withPrngValues
	}
}

// WithLogger specifies an optional hclog to use for db operations.  It's only
// valid for Open(..) and OpenWith(...). The logger provided can optionally
// implement the LogWriter interface as well which would override the default
// behavior for a logger (the default only emits postgres errors)
func WithLogger(l hclog.Logger) Option {
	return func(o *Options) {
		o.WithLogger = l
	}
}

// WithMaxOpenConnections specifies and optional max open connections for the
// database.  A value of zero equals unlimited connections
func WithMaxOpenConnections(max int) Option {
	return func(o *Options) {
		o.WithMaxOpenConnections = max
	}
}

// WithMinOpenConnections specifies and optional min open connections for the
// database.  A value of zero means that there is no min.
func WithMinOpenConnections(max int) Option {
	return func(o *Options) {
		o.WithMinOpenConnections = max
	}
}

// WithDebug specifies the given operation should invoke debug mode for the
// database output
func WithDebug(with bool) Option {
	return func(o *Options) {
		o.WithDebug = with
	}
}

// WithOnConflict specifies an optional on conflict criteria which specify
// alternative actions to take when an insert results in a unique constraint or
// exclusion constraint error
func WithOnConflict(onConflict *OnConflict) Option {
	return func(o *Options) {
		o.WithOnConflict = onConflict
	}
}

// WithReturnRowsAffected specifies an option for returning the rows affected
// and typically used with "bulk" write operations.
func WithReturnRowsAffected(rowsAffected *int64) Option {
	return func(o *Options) {
		o.WithRowsAffected = rowsAffected
	}
}

// WithTable specifies an option for setting a table name to use for the
// operation.
func WithTable(name string) Option {
	return func(o *Options) {
		o.WithTable = name
	}
}

// WithLogLevel specifies an option for setting the log level
func WithLogLevel(l LogLevel) Option {
	return func(o *Options) {
		o.withLogLevel = l
	}
}

// WithBatchSize specifies an option for setting the batch size for bulk
// operations like CreateItems. If WithBatchSize == 0, the default batch size is
// used (see DefaultBatchSize const).
func WithBatchSize(size int) Option {
	return func(o *Options) {
		o.WithBatchSize = size
	}
}
