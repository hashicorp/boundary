// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package daemon

import (
	"context"
)

type options struct {
	withDebug bool
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

// WithDebug provides an optional debug flag.
func WithDebug(_ context.Context, debug bool) Option {
	return func(o *options) error {
		o.withDebug = debug
		return nil
	}
}
