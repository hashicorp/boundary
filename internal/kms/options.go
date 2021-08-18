package kms

import (
	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLimit             int
	withRootWrapper       wrapping.Wrapper
	withWorkerAuthWrapper wrapping.Wrapper
	withRecoveryWrapper   wrapping.Wrapper
	withRepository        *Repository
	withOrderByVersion    db.OrderBy
	withKeyId             string
}

func getDefaultOptions() options {
	return options{}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are returned. If
// WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithRootWrapper sets the external root wrapper for a given scope
func WithRootWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withRootWrapper = w
	}
}

// WithWorkerAuthWrapper sets the external worker authentication wrapper for a
// given scope
func WithWorkerAuthWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withWorkerAuthWrapper = w
	}
}

// WithRecoveryWrapper sets the recovery wrapper for a given scope
func WithRecoveryWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withRecoveryWrapper = w
	}
}

// WithRepository sets a repository for a given wrapper lookup, useful if in the
// middle of a transaction where the reader/writer need to be specified
func WithRepository(repo *Repository) Option {
	return func(o *options) {
		o.withRepository = repo
	}
}

// WithOrderByVersion provides an option to specify ordering by the
// CreateTime field.
func WithOrderByVersion(orderBy db.OrderBy) Option {
	const col = "version"
	return func(o *options) {
		o.withOrderByVersion = orderBy
	}
}

// WithKeyId allows specifying a key ID that should be found in a scope's
// multiwrapper; if it is not found, keys will be refreshed
func WithKeyId(keyId string) Option {
	return func(o *options) {
		o.withKeyId = keyId
	}
}
