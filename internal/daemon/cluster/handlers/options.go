// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package handlers

import (
	"github.com/hashicorp/nodeenrollment/types"
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
	withNodeInfo *types.NodeInformation
}

func getDefaultOptions() options {
	return options{}
}

// WithNodeInfo provides an option types.NodeInformation
func WithNodeInfo(nodeInfo *types.NodeInformation) Option {
	return func(o *options) {
		o.withNodeInfo = nodeInfo
	}
}
