// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package encrypt

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o != nil {
			o(&opts)
		}
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withWrapper              wrapping.Wrapper
	withSalt                 []byte
	withInfo                 []byte
	withFilterOperations     map[DataClassification]FilterOperation
	withPointerstructureInfo *pointerstructureInfo
	withIgnoreTaggable       bool
	withTrackedMaps          *trackedMaps
}

func getDefaultOptions() options {
	return options{}
}

// WithWrapper defines an optional wrapper.
func WithWrapper(wrapper wrapping.Wrapper) Option {
	return func(o *options) {
		o.withWrapper = wrapper
	}
}

// WithSalt defines optional salt.
func WithSalt(salt []byte) Option {
	return func(o *options) {
		o.withSalt = salt
	}
}

// WithInfo defines optional info.
func WithInfo(info []byte) Option {
	return func(o *options) {
		o.withInfo = info
	}
}

func withFilterOperations(ops map[DataClassification]FilterOperation) Option {
	return func(o *options) {
		o.withFilterOperations = ops
	}
}

type pointerstructureInfo struct {
	i       interface{}
	pointer string
}

func withPointer(i interface{}, pointer string) Option {
	return func(o *options) {
		o.withPointerstructureInfo = &pointerstructureInfo{
			i:       i,
			pointer: pointer,
		}
	}
}

func withIgnoreTaggable() Option {
	return func(o *options) {
		o.withIgnoreTaggable = true
	}
}
