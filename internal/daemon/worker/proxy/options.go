// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package proxy

import (
	"net"

	serverpb "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
)

// Option - how Options are passed as arguments.
type Option func(*Options)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) Options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Options = how options are represented
type Options struct {
	WithInjectedApplicationCredentials []*serverpb.Credential
	WithPostConnectionHook             func(net.Conn)
}

func getDefaultOptions() Options {
	return Options{
		WithInjectedApplicationCredentials: nil,
		WithPostConnectionHook:             nil,
	}
}

// WithInjectedApplicationCredentials provides an optional injected application
// credentials to use when establishing a proxy
func WithInjectedApplicationCredentials(creds []*serverpb.Credential) Option {
	return func(o *Options) {
		o.WithInjectedApplicationCredentials = creds
	}
}

// WithPostConnectionHook provides a hook function to be called after a
// connection is established in a dialFunction.  When a dialer accepts
// WithPostConnectionHook the passed in function should be called prior to any
// other blocking call.
func WithPostConnectionHook(fn func(net.Conn)) Option {
	return func(o *Options) {
		o.WithPostConnectionHook = fn
	}
}
