// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"crypto/rand"
	"io"

	"github.com/hashicorp/boundary/internal/pagination"
)

// GetOpts - iterate the inbound Options and return a struct.
func GetOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withName               string
	withDescription        string
	WithLoginName          string
	withLimit              int
	withConfig             Configuration
	withPublicId           string
	password               string
	withPassword           bool
	withOrderByCreateTime  bool
	ascending              bool
	withStartPageAfterItem pagination.Item
	withRandomReader       io.Reader
}

func getDefaultOptions() options {
	return options{
		withConfig:       NewArgon2Configuration(),
		withRandomReader: rand.Reader,
	}
}

// WithPublicId provides an optional public id
func WithPublicId(id string) Option {
	return func(o *options) {
		o.withPublicId = id
	}
}

// WithDescription provides an optional description.
func WithDescription(desc string) Option {
	return func(o *options) {
		o.withDescription = desc
	}
}

// WithName provides an optional name.
func WithName(name string) Option {
	return func(o *options) {
		o.withName = name
	}
}

// WithLoginName provides an optional login name.
func WithLoginName(loginName string) Option {
	return func(o *options) {
		o.WithLoginName = loginName
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithPassword provides an optional password.
func WithPassword(password string) Option {
	return func(o *options) {
		o.password = password
		o.withPassword = true
	}
}

// WithConfiguration provides an optional configuration.
func WithConfiguration(config Configuration) Option {
	return func(o *options) {
		o.withConfig = config
	}
}

// WithOrderByCreateTime provides an option to specify ordering by the
// CreateTime field.
func WithOrderByCreateTime(ascending bool) Option {
	return func(o *options) {
		o.withOrderByCreateTime = true
		o.ascending = ascending
	}
}

// WithStartPageAfterItem is used to paginate over the results.
// The next page will start after the provided item.
func WithStartPageAfterItem(item pagination.Item) Option {
	return func(o *options) {
		o.withStartPageAfterItem = item
	}
}

// WithRandomReader provides an option to specify a random reader.
func WithRandomReader(reader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = reader
	}
}
