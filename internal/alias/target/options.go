// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"errors"

	"github.com/hashicorp/boundary/internal/pagination"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) (options, error) {
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
	withName               string
	withDescription        string
	withDestinationId      string
	withHostId             string
	withLimit              int
	withStartPageAfterItem pagination.Item
}

func getDefaultOptions() options {
	return options{}
}

// WithName provides an option to provide a name.
func WithName(name string) Option {
	return func(o *options) error {
		o.withName = name
		return nil
	}
}

// WithDescription provides an option to provide a description.
func WithDescription(desc string) Option {
	return func(o *options) error {
		o.withDescription = desc
		return nil
	}
}

// WithDestinationId provides an option to provide a destination id.
func WithDestinationId(id string) Option {
	return func(o *options) error {
		o.withDestinationId = id
		return nil
	}
}

// WithHostId provides an option to provide a host id.
func WithHostId(id string) Option {
	return func(o *options) error {
		o.withHostId = id
		return nil
	}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) error {
		o.withLimit = l
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
		o.withStartPageAfterItem = item
		return nil
	}
}
