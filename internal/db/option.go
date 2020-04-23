package db

import (
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(Options)

// Options = how options are represented
type Options map[string]interface{}

func getDefaultOptions() Options {
	return Options{
		optionWithOplog:    false,
		optionWithWrapper:  nil,
		optionWithMetadata: oplog.Metadata{},
		optionWithDebug:    false,
		optionWithLookup:   true, // optionWithLookup is true by default,
	}
}

const optionWithLookup = "optionWithLookup"

// WithLookup is true by default, so you're disabling the lookup
func WithLookup(disabled bool) Option {
	return func(o Options) {
		o[optionWithLookup] = disabled
	}
}

const optionWithDebug = "optionWithDebug"

// WithDebug enables debug
func WithDebug(enable bool) Option {
	return func(o Options) {
		o[optionWithDebug] = enable
	}
}

const optionWithOplog = "optionWithOplog"

// WithOplog provides an option to write an oplog entry
func WithOplog(withOplog bool) Option {
	return func(o Options) {
		o[optionWithOplog] = withOplog
	}
}

const optionWithWrapper = "optionWithWrapper"

// WithWrapper provides an optional kms wrapper
func WithWrapper(wrapper wrapping.Wrapper) Option {
	return func(o Options) {
		o[optionWithWrapper] = wrapper
	}
}

const optionWithMetadata = "optionWithMetadata"

// WithMetadata provides an optional metadata
func WithMetadata(md oplog.Metadata) Option {
	return func(o Options) {
		o[optionWithMetadata] = md
	}
}
