// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"github.com/hashicorp/go-dbw"
	"github.com/hashicorp/go-hclog"
)

type options struct {
	withSchemaVersion    string
	withDebug            bool
	withUrl              string
	withDbType           dbw.DbType
	withGormFormatter    hclog.Logger
	withForceResetSchema bool
}

// Option - how options are passed as args
type Option func(*options) error

func getDefaultOptions() options {
	return options{
		withDbType: dbw.Sqlite,
	}
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

func WithGormFormatter(logger hclog.Logger) Option {
	return func(o *options) error {
		o.withGormFormatter = logger
		return nil
	}
}

// withTestValidSchemaVersion provides optional valid schema version for testing
// purposes. This is used to simulate a schema version that is valid/invalid.
func withTestValidSchemaVersion(useVersion string) Option {
	return func(o *options) error {
		o.withSchemaVersion = useVersion
		return nil
	}
}

// WithUrls provides optional url
func WithUrl(url string) Option {
	return func(o *options) error {
		o.withUrl = url
		return nil
	}
}

// WithDebug provides an optional debug flag.
func WithDebug(debug bool) Option {
	return func(o *options) error {
		o.withDebug = debug
		return nil
	}
}

// WithForceResetSchema provides an optional way to force resetting the cache
func WithForceResetSchema(debug bool) Option {
	return func(o *options) error {
		o.withForceResetSchema = debug
		return nil
	}
}
