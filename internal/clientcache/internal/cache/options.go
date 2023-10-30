// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	"github.com/hashicorp/go-dbw"
)

type options struct {
	withUpdateLastAccessedTime bool
	withDbType                 dbw.DbType
	withAuthTokenId            string
	withUserId                 string
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

// WithUpdateLastAccessedTime provides an option for updating the last access time
func WithUpdateLastAccessedTime(b bool) Option {
	return func(o *options) error {
		o.withUpdateLastAccessedTime = b
		return nil
	}
}

// withUserId provides an option for providing an auth token id
func withAuthTokenId(id string) Option {
	return func(o *options) error {
		o.withAuthTokenId = id
		return nil
	}
}

// withUserId provides an option for providing a user id
func withUserId(id string) Option {
	return func(o *options) error {
		o.withUserId = id
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
