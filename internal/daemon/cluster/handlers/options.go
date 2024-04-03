// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"crypto/rand"
	"io"

	"github.com/hashicorp/nodeenrollment"
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
	withKeyProducer  nodeenrollment.X25519KeyProducer
	withRandomReader io.Reader
}

func getDefaultOptions() options {
	return options{
		withRandomReader: rand.Reader,
	}
}

// WithKeyProducer provides an option types.NodeInformation
func WithKeyProducer(nodeInfo nodeenrollment.X25519KeyProducer) Option {
	return func(o *options) {
		o.withKeyProducer = nodeInfo
	}
}

// WithRandomReader provides an option to specify a specific random source
func WithRandomReader(with io.Reader) Option {
	return func(o *options) {
		o.withRandomReader = with
	}
}
