// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"

	"github.com/hashicorp/boundary/internal/pagination"
)

// The option type is how options are passed as arguments
type Option func(*Options) error

// Options is a struct that contains all the possible auth options
type Options struct {
	WithLimit               int
	WithStartPageAfterItem  pagination.Item
	WithUnauthenticatedUser bool
}

// getDefaultOptions returns a new Options struct
func getDefaultOptions() *Options {
	return &Options{}
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

// WithLimit provides an option to provide a limit.
// If WithLimit <= 0, then default limits are used for results.
func WithLimit(_ context.Context, l int) Option {
	return func(o *Options) error {
		o.WithLimit = l
		return nil
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(_ context.Context, item pagination.Item) Option {
	return func(o *Options) error {
		o.WithStartPageAfterItem = item
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
