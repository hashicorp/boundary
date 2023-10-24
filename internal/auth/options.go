// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"errors"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

type Option func(*Options) error

type Options struct {
	WithLimit               int
	WithStartPageAfterItem  pagination.Item
	WithReader              db.Reader
	WithWriter              db.Writer
	WithUnauthenticatedUser bool
}

func getDefaultOptions() *Options {
	return &Options{
		WithLimit: -1,
	}
}

// GetOpts loops over the options and provides
// the configured options struct
func GetOpts(opts ...Option) (*Options, error) {
	newOpts := getDefaultOptions()
	for _, opt := range opts {
		if err := opt(newOpts); err != nil {
			return nil, err
		}
	}
	return newOpts, nil
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(_ context.Context, l int) Option {
	return func(o *Options) error {
		o.WithLimit = l
		return nil
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *Options) error {
		o.WithStartPageAfterItem = item
		return nil
	}
}

// WithReaderWriter allows the caller to pass an inflight transaction to be used
// for all database operations. If WithReaderWriter(...) is used, then the
// caller is responsible for managing the transaction.
func WithReaderWriter(_ context.Context, r db.Reader, w db.Writer) Option {
	return func(o *Options) error {
		switch {
		case util.IsNil(r):
			return errors.New("nil reader")
		case util.IsNil(w):
			return errors.New("nil writer")
		}
		o.WithReader = r
		o.WithWriter = w
		return nil
	}
}

// WithUnauthenticatedUser provides an option for filtering results for
// an unauthenticated users.
func WithUnauthenticatedUser(_ context.Context, enabled bool) Option {
	return func(o *Options) error {
		o.WithUnauthenticatedUser = enabled
		return nil
	}
}
