// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package bsr

import "github.com/hashicorp/boundary/internal/bsr/kms"

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
	withSupportsMultiplex bool
	withKeys              *kms.Keys
	withSha256Sum         []byte
}

func getDefaultOptions() options {
	return options{
		withSupportsMultiplex: false,
		withKeys:              nil,
		withSha256Sum:         nil,
	}
}

// WithSupportsMultiplex is used indicate that a protocol supports multiplexing
// and therefore a BSR can contain Channels.
func WithSupportsMultiplex(b bool) Option {
	return func(o *options) {
		o.withSupportsMultiplex = b
	}
}

// WithKeys is used to provide optional kms.Keys.
func WithKeys(k *kms.Keys) Option {
	return func(o *options) {
		o.withKeys = k
	}
}

// WithSha256Sum is used to provide a hex encoded SHA256SUM.
func WithSha256Sum(b []byte) Option {
	return func(o *options) {
		o.withSha256Sum = b
	}
}
