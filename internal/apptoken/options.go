// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
)

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

// options = how options are represented
type options struct {
	withRecursive          bool
	withLimit              int
	withStartPageAfterItem pagination.Item
}

func getDefaultOptions() options {
	return options{
		withLimit: db.DefaultLimit,
	}
}

// WithRecursive indicates that this request is a recursive request
func WithRecursive(isRecursive bool) Option {
	return func(o *options) {
		o.withRecursive = isRecursive
	}
}

// WithLimit provides an option to provide a limit.
// If WithLimit <= 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		if limit > 0 {
			o.withLimit = limit
		} else {
			o.withLimit = db.DefaultLimit
		}
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}
