package kms

import (
	"github.com/hashicorp/go-hclog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
)

func getOpts(opt ...Option) Options {
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
	withLogger            hclog.Logger
	withRootWrapper       wrapping.Wrapper
	withWorkerAuthWrapper wrapping.Wrapper
}

func getDefaultOptions() Options {
	return Options{}
}

func WithLogger(l hclog.Logger) Option {
	return func(o *Options) {
		o.withLogger = l
	}
}

func WithRootWrapper(w wrapping.Wrapper) Option {
	return func(o *Options) {
		o.withRootWrapper = w
	}
}

func WithWorkerAuthWrapper(w wrapping.Wrapper) Option {
	return func(o *Options) {
		o.withRootWrapper = w
	}
}
