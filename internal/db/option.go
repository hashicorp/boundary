package db

import (
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/watchtower/internal/oplog"
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
	withOplog  bool
	oplogOpts  oplogOpts
	withDebug  bool
	withLookup bool
}

type oplogOpts struct {
	wrapper  wrapping.Wrapper
	metadata oplog.Metadata
}

func getDefaultOptions() options {
	return options{
		withOplog: false,
		oplogOpts: oplogOpts{
			wrapper:  nil,
			metadata: oplog.Metadata{},
		},
		withDebug:  false,
		withLookup: false,
	}
}

// WithLookup enables a lookup
func WithLookup(enable bool) Option {
	return func(o *options) {
		o.withLookup = enable
	}
}

// WithDebug enables debug
func WithDebug(enable bool) Option {
	return func(o *options) {
		o.withDebug = enable
	}
}

// WithOplog provides an option to write an oplog entry
func WithOplog(wrapper wrapping.Wrapper, md oplog.Metadata) Option {
	return func(o *options) {
		o.withOplog = true
		o.oplogOpts = oplogOpts{
			wrapper:  wrapper,
			metadata: md,
		}
	}
}
