// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-dbw"
)

type options struct {
	withBoundaryAddress        string
	withAuthTokenId            string
	withAuthToken              string
	withDebug                  bool
	withUrl                    string
	withUpdateLastAccessedTime bool
	withDbType                 dbw.DbType
	withTargetRetrievalFunc    TargetRetrievalFunc
	withSessionRetrievalFunc   SessionRetrievalFunc
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

// WithUpdateLastAccessedTime provides an option for updating the last access time
func WithUpdateLastAccessedTime(b bool) Option {
	return func(o *options) error {
		o.withUpdateLastAccessedTime = b
		return nil
	}
}

// WithBoundaryAddress provides an option for specifying a boundary address
func WithBoundaryAddress(a string) Option {
	return func(o *options) error {
		o.withBoundaryAddress = a
		return nil
	}
}

// WithAuthTokenId provides an option for specifying an auth token id
func WithAuthTokenId(id string) Option {
	return func(o *options) error {
		o.withAuthTokenId = id
		return nil
	}
}

// WithAuthToken provides an option for specifying an auth token id
func WithAuthToken(token string) Option {
	return func(o *options) error {
		if len(strings.Split(token, "_")) != 3 {
			return fmt.Errorf("provided token %q cannot be parsed as an auth token", token)
		}
		o.withAuthToken = token
		return nil
	}
}

// WithTargetRetrievalFunc provides an option for specifying a targetRetrievalFunc
func WithTargetRetrievalFunc(fn TargetRetrievalFunc) Option {
	return func(o *options) error {
		o.withTargetRetrievalFunc = fn
		return nil
	}
}

// WithSessionRetrievalFunc provides an option for specifying a sessionRetrievalFunc
func WithSessionRetrievalFunc(fn SessionRetrievalFunc) Option {
	return func(o *options) error {
		o.withSessionRetrievalFunc = fn
		return nil
	}
}
