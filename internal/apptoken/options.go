// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

func getDefaultOptions() options {
	return options{}
}

// options = how options are represented
type options struct {
	withRecursive bool
}

// WithRecursive indicates that this request is a recursive request
func WithRecursive(isRecursive bool) Option {
	return func(o *options) {
		o.withRecursive = isRecursive
	}
}
