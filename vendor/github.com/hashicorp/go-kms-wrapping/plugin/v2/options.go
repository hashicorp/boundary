// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"errors"

	"github.com/hashicorp/go-hclog"
	gp "github.com/hashicorp/go-plugin"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case OptionFunc:
			to(opts)
		default:
			return nil, errors.New("option passed in that does not belong to this package")
		}
	}
	return opts, nil
}

type options struct {
	withLogger       hclog.Logger
	withSecureConfig *gp.SecureConfig
}

// Option - a type that wraps an interface for compile-time safety but can
// contain an option for this package or for wrappers implementing this
// interface.
type Option func() interface{}

// OptionFunc - a type for funcs that operate on the shared Options struct. The
// options below explicitly wrap this so that we can switch on it when parsing
// opts for various wrappers.
type OptionFunc func(*options)

func getDefaultOptions() *options {
	return &options{}
}

// WithLogger allows passing a logger to the plugin library for debugging
func WithLogger(with hclog.Logger) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) {
			o.withLogger = with
		})
	}
}

// WithSecureConfig allows passing a secure configuration param
func WithSecureConfig(with *gp.SecureConfig) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) {
			o.withSecureConfig = with
		})
	}
}
