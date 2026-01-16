// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"errors"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if err := o(&opts); err != nil {
			return opts, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments.
type Option func(*options) error

// options = how options are represented
type options struct {
	WithLimit              int
	WithReader             db.Reader
	WithWriter             db.Writer
	WithOrderByCreateTime  bool
	Ascending              bool
	WithStartPageAfterItem pagination.Item
}

func getDefaultOptions() options {
	return options{}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) error {
		o.WithLimit = l
		return nil
	}
}

// WithOrderByCreateTime provides an option to specify ordering by the
// CreateTime field.
func WithOrderByCreateTime(ascending bool) Option {
	return func(o *options) error {
		o.WithOrderByCreateTime = true
		o.Ascending = ascending
		return nil
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) error {
		if item == nil {
			return errors.New("item cannot be nil")
		}
		o.WithStartPageAfterItem = item
		return nil
	}
}

// WithReaderWriter is used to share the same database reader
// and writer when executing sql within a transaction.
func WithReaderWriter(r db.Reader, w db.Writer) Option {
	return func(o *options) error {
		if util.IsNil(r) {
			return errors.New("reader cannot be nil")
		}
		if util.IsNil(w) {
			return errors.New("writer cannot be nil")
		}
		o.WithReader = r
		o.WithWriter = w
		return nil
	}
}
