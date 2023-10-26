// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
)

type options struct {
	withName        string
	withDescription string
	withLimit       int
}

// Option - how options are passed as args
type Option func(*options) error

func getDefaultOptions() options {
	return options{}
}

func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()

	for _, o := range opt {
		if err := o(&opts); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

// WithName provides an optional name.
func WithName(_ context.Context, n string) Option {
	return func(o *options) error {
		o.withName = n
		return nil
	}
}

// WithDescription provides an optional description.
func WithDescription(_ context.Context, desc string) Option {
	return func(o *options) error {
		o.withDescription = desc
		return nil
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.
func WithLimit(_ context.Context, limit int) Option {
	return func(o *options) error {
		o.withLimit = limit
		return nil
	}
}
