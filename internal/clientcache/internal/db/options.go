// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package db

import (
	"github.com/hashicorp/go-dbw"
)

type options struct {
	withDebug  bool
	withUrl    string
	withDbType dbw.DbType
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
