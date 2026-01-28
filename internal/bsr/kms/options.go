// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package kms

import (
	"io"

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
	withBsrWrapper    wrapping.Wrapper
	withRandomReader  io.Reader
	withAlreadyLocked bool
}

func getDefaultOptions() options {
	return options{}
}

// WithBsrWrapper sets the external Bsr wrapper for a KMS
func WithBsrWrapper(w wrapping.Wrapper) Option {
	return func(o *options) {
		o.withBsrWrapper = w
	}
}

// WithRandomReader(...) option allows an optional random reader to be
// provided.  By default the reader from crypto/rand will be used.
func WithRandomReader(randomReader io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = randomReader
	}
}

// not exported... just an internal option
func withAlreadyLocked(isLockedAlready bool) Option {
	return func(o *options) {
		o.withAlreadyLocked = isLockedAlready
	}
}
