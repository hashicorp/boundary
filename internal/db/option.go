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
		optionWithCommit:   false,
		optionWithWrapper:  nil,
		optionWithMetadata: oplog.Metadata{},
		optionWithDebug:    false,
	}
}

const optionWithDebug = "optionWithDebug"

// WithDebug enables debug
func WithDebug(enable bool) Option {
	return func(o Options) {
		o[optionWithDebug] = enable
	}
}

const optionWithCommit = "optionWithCommit"

// WithCommit provides an option to commit the transaction
func WithCommit(commitTx bool) Option {
	return func(o Options) {
		o[optionWithCommit] = commitTx
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

// WithWrapper provides an optional kms wrapper
func WithMetadata(md oplog.Metadata) Option {
	return func(o Options) {
		o[optionWithMetadata] = md
	}
}
