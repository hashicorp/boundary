// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cache

import (
	stderrors "errors"

	"github.com/hashicorp/go-dbw"
)

type testRefreshWaitChs struct {
	firstSempahore  chan struct{}
	secondSemaphore chan struct{}
}

type options struct {
	withUpdateLastAccessedTime       bool
	withDbType                       dbw.DbType
	withAuthTokenId                  string
	withUserId                       string
	withResolvableAliasRetrievalFunc ResolvableAliasRetrievalFunc
	withTargetRetrievalFunc          TargetRetrievalFunc
	withSessionRetrievalFunc         SessionRetrievalFunc
	withIgnoreSearchStaleness        bool
	withMaxResultSetSize             int
	withTestRefreshWaitChs           *testRefreshWaitChs
	withUseNonPagedListing           bool
}

// Option - how options are passed as args
type Option func(*options) error

func getDefaultOptions() options {
	return options{
		withDbType:           dbw.Sqlite,
		withMaxResultSetSize: defaultLimitedResultSetSize,
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

// WithAliasRetrievalFunc provides an option for specifying an aliasRetrievalFunc
func WithAliasRetrievalFunc(fn ResolvableAliasRetrievalFunc) Option {
	return func(o *options) error {
		o.withResolvableAliasRetrievalFunc = fn
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

// WithIgnoreSearchStaleness provides an option for ignoring the resource
// staleness when performing a search.
func WithIgnoreSearchStaleness(b bool) Option {
	return func(o *options) error {
		o.withIgnoreSearchStaleness = b
		return nil
	}
}

// WithMaxResultSetSize provides an option for limiting the result set, e.g.
// when no filter is provided on a list. A 0 does nothing (keeps the default).
func WithMaxResultSetSize(with int) Option {
	return func(o *options) error {
		switch {
		case with == 0:
			return nil
		case with < -1:
			return stderrors.New("max result set size must be -1 or greater")
		}
		o.withMaxResultSetSize = with
		return nil
	}
}

// WithTestRefreshWaitChs provides an option for specifying channels to wait on
// before proceeding. This allows testing the logic that ensures only one is
// running at a time.
func WithTestRefreshWaitChs(with *testRefreshWaitChs) Option {
	return func(o *options) error {
		o.withTestRefreshWaitChs = with
		return nil
	}
}

// WithUseNonPagedListing provides an option for ignoring the resource
// staleness when performing a search.
func WithUseNonPagedListing(b bool) Option {
	return func(o *options) error {
		o.withUseNonPagedListing = b
		return nil
	}
}
