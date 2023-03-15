// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package fstest

import (
	"context"
	"io/fs"

	"github.com/hashicorp/boundary/internal/storage"
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

// NewFunc is a function called in New.
// It can be used to simulate an error during New.
type NewFunc func(context.Context, string) (storage.Container, error)

// CloseFunc is a function called at close.
// It can be used to simulate an error during Close.
type CloseFunc func() error

// StatFunc is a function called for Stat.
// It can be used to simulate an error on calls to Stat
type StatFunc func() (fs.FileInfo, error)

// options = how options are represented
type options struct {
	withNewFunc   NewFunc
	withCloseFunc CloseFunc
	withStatFunc  StatFunc
}

func getDefaultOptions() options {
	return options{
		withNewFunc:   nil,
		withCloseFunc: nil,
		withStatFunc:  nil,
	}
}

// WithNewFunc is used to provide a custom new function.
func WithNewFunc(f NewFunc) Option {
	return func(o *options) {
		o.withNewFunc = f
	}
}

// WithCloseFunc is used to provide a custom close function.
func WithCloseFunc(f CloseFunc) Option {
	return func(o *options) {
		o.withCloseFunc = f
	}
}

// WithStatFunc is used to provide a custom Stat function.
func WithStatFunc(f StatFunc) Option {
	return func(o *options) {
		o.withStatFunc = f
	}
}
