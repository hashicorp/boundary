// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"io"

	"github.com/hashicorp/boundary/internal/db"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// getOpts - iterate the inbound Options and return a struct
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withLimit                    int
	withRootWrapper              wrapping.Wrapper
	withWorkerAuthWrapper        wrapping.Wrapper
	withWorkerAuthStorageWrapper wrapping.Wrapper
	withRecoveryWrapper          wrapping.Wrapper
	withBsrWrapper               wrapping.Wrapper
	withOrderByVersion           db.OrderBy
	withKeyId                    string
	withScopeIds                 []string
	withRandomReader             io.Reader
	withReader                   db.Reader
	withWriter                   db.Writer
	withRewrap                   bool
}

func getDefaultOptions() options {
	return options{}
}

// WithLimit provides an option to provide a limit. Intentionally allowing
// negative integers. If WithLimit < 0, then unlimited results are returned. If
// WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithRootWrapper sets the external root wrapper for a given scope
func WithRootWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withRootWrapper = w
	}
}

// WithWorkerAuthWrapper sets the external worker authentication wrapper for a
// given scope
func WithWorkerAuthWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withWorkerAuthWrapper = w
	}
}

// WithWorkerAuthStorageWrapper sets the external pki worker storage wrapper for a
// given scope
func WithWorkerAuthStorageWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withWorkerAuthStorageWrapper = w
	}
}

// WithRecoveryWrapper sets the recovery wrapper for a given scope
func WithRecoveryWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withRecoveryWrapper = w
	}
}

// WithBsrWrapper sets the external Bsr wrapper for a KMS
func WithBsrWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withBsrWrapper = w
	}
}

// WithOrderByVersion provides an option to specify ordering by the
// CreateTime field.
func WithOrderByVersion(orderBy db.OrderBy) Option {
	const col = "version"
	return func(o *options) {
		o.withOrderByVersion = orderBy
	}
}

// WithKeyId allows specifying a key ID that should be found in a scope's
// multiwrapper; if it is not found, keys will be refreshed
func WithKeyId(keyId string) Option {
	return func(o *options) {
		o.withKeyId = keyId
	}
}

// WithScopeIds allows the specifying of optional scope ids.
func WithScopeIds(scopeId ...string) Option {
	return func(o *options) {
		o.withScopeIds = scopeId
	}
}

// WithRandomReader(...) option allows an optional random reader to be
// provided.  By default the reader from crypto/rand will be used.
func WithRandomReader(randomReader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = randomReader
	}
}

// WithReaderWriter allows the caller to pass an inflight transaction to be used
// for all database operations. If WithReaderWriter(...) is used, then the
// caller is responsible for managing the transaction. The purpose of the
// WithReaderWriter(...) option is to allow the caller to create the scope and
// all of its keys in the same transaction.
func WithReaderWriter(r db.Reader, w db.Writer) Option {
	return func(o *options) {
		o.withReader = r
		o.withWriter = w
	}
}

// WithRewrap allows for optionally specifying that the keys should be
// rewrapped.
func WithRewrap(enableRewrap bool) Option {
	return func(o *options) {
		o.withRewrap = enableRewrap
	}
}
