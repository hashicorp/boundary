package db

import (
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*Options)

// Options - how Options are represented.
type Options struct {
	withOplog  bool
	oplogOpts  oplogOpts
	withLookup bool
	// WithLimit must be accessible in other packages.
	WithLimit int
	// WithFieldMaskPaths must be accessible from other packages.
	WithFieldMaskPaths []string
	// WithNullPaths must be accessible from other packages.
	WithNullPaths []string

	newOplogMsg  *oplog.Message
	newOplogMsgs *[]*oplog.Message

	// WithVersion must be accessible from other packages.
	WithVersion *uint32

	withSkipVetForWrite bool

	withWhereClause     string
	withWhereClauseArgs []interface{}
	withOrder           string

	// withPrngValues is used to switch the ID generation to a pseudo-random mode
	withPrngValues []string

	withGormFormatter      hclog.Logger
	withMaxOpenConnections int

	// withDebug indicates that the given operation should invoke Gorm's debug
	// mode
	withDebug bool

	withOnConflict   *OnConflict
	withRowsAffected *int64
}

type oplogOpts struct {
	wrapper  wrapping.Wrapper
	metadata oplog.Metadata
}

func getDefaultOptions() Options {
	return Options{
		withOplog: false,
		oplogOpts: oplogOpts{
			wrapper:  nil,
			metadata: oplog.Metadata{},
		},
		withLookup:         false,
		WithFieldMaskPaths: []string{},
		WithNullPaths:      []string{},
		WithLimit:          0,
		WithVersion:        nil,
	}
}

// WithLookup enables a lookup.
func WithLookup(enable bool) Option {
	return func(o *Options) {
		o.withLookup = enable
	}
}

// WithOplog provides an option to write an oplog entry. WithOplog and
// NewOplogMsg cannot be used together.
func WithOplog(wrapper wrapping.Wrapper, md oplog.Metadata) Option {
	return func(o *Options) {
		o.withOplog = true
		o.oplogOpts = oplogOpts{
			wrapper:  wrapper,
			metadata: md,
		}
	}
}

// NewOplogMsg provides an option to ask for a new in-memory oplog message.  The
// new msg will be returned in the provided *oplog.Message parameter. WithOplog
// and NewOplogMsg cannot be used together.
func NewOplogMsg(msg *oplog.Message) Option {
	return func(o *Options) {
		o.newOplogMsg = msg
	}
}

// NewOplogMsgs provides an option to ask for multiple new in-memory oplog
// messages.  The new msgs will be returned in the provided *[]oplog.Message
// parameter. NewOplogMsgs can only be used with write functions that operate on
// multiple items(CreateItems, DeleteItems). WithOplog and NewOplogMsgs cannot
// be used together.
func NewOplogMsgs(msgs *[]*oplog.Message) Option {
	return func(o *Options) {
		o.newOplogMsgs = msgs
	}
}

// WithFieldMaskPaths provides an option to provide field mask paths.
func WithFieldMaskPaths(paths []string) Option {
	return func(o *Options) {
		o.WithFieldMaskPaths = paths
	}
}

// WithNullPaths provides an option to provide null paths.
func WithNullPaths(paths []string) Option {
	return func(o *Options) {
		o.WithNullPaths = paths
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *Options) {
		o.WithLimit = limit
	}
}

// WithVersion provides an option version number for update operations.
func WithVersion(version *uint32) Option {
	return func(o *Options) {
		o.WithVersion = version
	}
}

// WithSkipVetForWrite provides an option to allow skipping vet checks to allow
// testing lower-level SQL triggers and constraints
func WithSkipVetForWrite(enable bool) Option {
	return func(o *Options) {
		o.withSkipVetForWrite = enable
	}
}

// WithWhere provides an option to provide a where clause with arguments for an
// operation.
func WithWhere(whereClause string, args ...interface{}) Option {
	return func(o *Options) {
		o.withWhereClause = whereClause
		o.withWhereClauseArgs = append(o.withWhereClauseArgs, args...)
	}
}

// WithOrder provides an option to provide an order when searching and looking
// up.
func WithOrder(withOrder string) Option {
	return func(o *Options) {
		o.withOrder = withOrder
	}
}

// WithPrngValues provides an option to provide values to seed an PRNG when generating IDs
func WithPrngValues(withPrngValues []string) Option {
	return func(o *Options) {
		o.withPrngValues = withPrngValues
	}
}

// WithGormFormatter specifies an optional hclog to use for gorm's log
// formmater
func WithGormFormatter(l hclog.Logger) Option {
	return func(o *Options) {
		o.withGormFormatter = l
	}
}

// WithMaxOpenConnections specifices and optional max open connections for the
// database
func WithMaxOpenConnections(max int) Option {
	return func(o *Options) {
		o.withMaxOpenConnections = max
	}
}

// WithDebug specifies the given operation should invoke debug mode in Gorm
func WithDebug(with bool) Option {
	return func(o *Options) {
		o.withDebug = with
	}
}

// WithOnConflict specifies an optional on conflict criteria which specify
// alternative actions to take when an insert results in a unique constraint or
// exclusion constraint error
func WithOnConflict(onConflict *OnConflict) Option {
	return func(o *Options) {
		o.withOnConflict = onConflict
	}
}

// WithReturnRowsAffected specifies an option for returning the rows affected
func WithReturnRowsAffected(rowsAffected *int64) Option {
	return func(o *Options) {
		o.withRowsAffected = rowsAffected
	}
}
