package handlers

import "github.com/hashicorp/go-hclog"

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments. Some of these are used for
// types within the handlers package, and some are for handlers to re-use across
// the various handler types.
type Option func(*options)

// options = how options are represented
type options struct {
	withDiscardUnknownFields bool
	WithLogger               hclog.Logger
}

func getDefaultOptions() options {
	return options{}
}

// WithDiscardUnknownFields provides an option to cause StructToProto to ignore
// unknown fields. This is useful in some instances when we need to unmarshal a
// value from a pb.Struct after we've added some custom extra fields.
func WithDiscardUnknownFields(discard bool) Option {
	return func(o *options) {
		o.withDiscardUnknownFields = discard
	}
}

// WithLogger provides an option include a logger
func WithLogger(logger hclog.Logger) Option {
	return func(o *options) {
		o.WithLogger = logger
	}
}
