// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/internal/util/template"
)

// GetOpts - iterate the inbound Options and return a struct
func GetOpts(opt ...Option) (*options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments.
type Option func(*options) error

// options = how options are represented
type options struct {
	WithTemplateData       template.Data
	WithReader             db.Reader
	WithWriter             db.Writer
	WithLimit              int
	WithStartPageAfterItem pagination.Item
	WithRandomReader       io.Reader
}

func getDefaultOptions() *options {
	return &options{
		WithRandomReader: rand.Reader,
	}
}

// WithTemplateData provides a way to pass in template information
func WithTemplateData(with template.Data) Option {
	return func(o *options) error {
		o.WithTemplateData = with
		return nil
	}
}

// WithReaderWriter allows the caller to pass an inflight transaction to be used
// for all database operations. If WithReaderWriter(...) is used, then the
// caller is responsible for managing the transaction.
func WithReaderWriter(r db.Reader, w db.Writer) Option {
	return func(o *options) error {
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

// WithLimit provides an option to provide a limit.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) error {
		if l < 0 {
			return errors.New("limit must be at least 0")
		}
		o.WithLimit = l
		return nil
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) error {
		o.WithStartPageAfterItem = item
		return nil
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) error {
		o.WithRandomReader = reader
		return nil
	}
}
