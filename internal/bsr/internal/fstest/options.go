// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	withNewFunc        NewFunc
	withCloseFunc      CloseFunc
	withStatFunc       StatFunc
	withReadOnly       bool
	withStorageOptions []storage.Option
	withOriginalFile   bool
}

func getDefaultOptions() options {
	return options{
		withNewFunc:        nil,
		withCloseFunc:      nil,
		withStatFunc:       nil,
		withReadOnly:       false,
		withStorageOptions: nil,
		withOriginalFile:   false,
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

// WithReadOnly is used to set a read only bool
func WithReadOnly(b bool) Option {
	return func(o *options) {
		o.withReadOnly = b
	}
}

// WithStorageOptions is used to pass through storage options.
func WithStorageOptions(opts []storage.Option) Option {
	return func(o *options) {
		o.withStorageOptions = opts
	}
}

// WithOriginalFile is used to decide if the original of a file
// should be returned instead of a copy of the file during
// opening a file.
func WithOriginalFile() Option {
	return func(o *options) {
		o.withOriginalFile = true
	}
}
