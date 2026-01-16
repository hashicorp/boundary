// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package log

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

// Options = how options are represented
type Options struct {
	WithDeleteLog bool
}

func getDefaultOptions() Options {
	return Options{}
}

// WithDeleteLog provides an option to specify the deletion of log entries.
func WithDeleteLog(del bool) Option {
	return func(o *Options) {
		o.WithDeleteLog = del
	}
}
