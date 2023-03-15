// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package bsr

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
	withSupportsMultiplex bool
}

func getDefaultOptions() options {
	return options{
		withSupportsMultiplex: false,
	}
}

// WithSupportsMultiplex is used indicate that a protocol supports multiplexing
// and therefore a BSR can contain Channels.
func WithSupportsMultiplex(b bool) Option {
	return func(o *options) {
		o.withSupportsMultiplex = b
	}
}
