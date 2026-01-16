// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
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
	withKeyProducer nodeenrollment.X25519KeyProducer
}

func getDefaultOptions() options {
	return options{}
}

// WithKeyProducer provides an option types.NodeInformation
func WithKeyProducer(nodeInfo nodeenrollment.X25519KeyProducer) Option {
	return func(o *options) {
		o.withKeyProducer = nodeInfo
	}
}
