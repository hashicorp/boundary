package db

import (
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog"
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
	withDebug  bool
	withLookup bool
	// WithLimit must be accessible in other packages.
	WithLimit int
	// WithFieldMaskPaths must be accessible from other packages.
	WithFieldMaskPaths []string
	// WithNullPaths must be accessible from other packages.
	WithNullPaths []string
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
		withDebug:          false,
		withLookup:         false,
		WithFieldMaskPaths: []string{},
		WithNullPaths:      []string{},
		WithLimit:          0,
	}
}

// WithLookup enables a lookup.
func WithLookup(enable bool) Option {
	return func(o *Options) {
		o.withLookup = enable
	}
}

// WithDebug enables debug.
func WithDebug(enable bool) Option {
	return func(o *Options) {
		o.withDebug = enable
	}
}

// WithOplog provides an option to write an oplog entry.
func WithOplog(wrapper wrapping.Wrapper, md oplog.Metadata) Option {
	return func(o *Options) {
		o.withOplog = true
		o.oplogOpts = oplogOpts{
			wrapper:  wrapper,
			metadata: md,
		}
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
