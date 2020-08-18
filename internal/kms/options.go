package kms

import (
	"github.com/hashicorp/go-hclog"
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
	withLogger            hclog.Logger
	withRootWrapper       wrapping.Wrapper
	withWorkerAuthWrapper wrapping.Wrapper
	withRepository        *Repository
	withOrder             string
}

func getDefaultOptions() options {
	return options{}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

func WithLogger(l hclog.Logger) Option {
	return func(o *options) {
		o.withLogger = l
	}
}

func WithRootWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withRootWrapper = w
	}
}

func WithWorkerAuthWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withWorkerAuthWrapper = w
	}
}

func WithRepository(repo *Repository) Option {
	return func(o *options) {
		o.withRepository = repo
	}
}

func WithOrder(order string) Option {
	return func(o *options) {
		o.withOrder = order
	}
}
