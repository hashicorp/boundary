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
		optionWithOplog: false,
		optionOplogArgs: oplogArgs{
			wrapper:  nil,
			metadata: oplog.Metadata{},
		},
		optionWithDebug:  false,
		optionWithLookup: false,
	}
}

const optionWithLookup = "optionWithLookup"

// WithLookup enables a lookup
func WithLookup(enable bool) Option {
	return func(o Options) {
		o[optionWithLookup] = enable
	}
}

const optionWithDebug = "optionWithDebug"

// WithDebug enables debug
func WithDebug(enable bool) Option {
	return func(o Options) {
		o[optionWithDebug] = enable
	}
}

type oplogArgs struct {
	wrapper  wrapping.Wrapper
	metadata oplog.Metadata
}

const optionWithOplog = "optionWithOplog"
const optionOplogArgs = "optionWithOplogArgs"

// WithOplog provides an option to write an oplog entry
func WithOplog(wrapper wrapping.Wrapper, md oplog.Metadata) Option {
	return func(o Options) {
		o[optionWithOplog] = true
		o[optionOplogArgs] = oplogArgs{
			wrapper:  wrapper,
			metadata: md,
		}
	}
}
