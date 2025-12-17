// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package edition

import "github.com/hashicorp/boundary/internal/db/schema/migration"

// getOpts - iterate the inbound Options and return a struct.
func getOpts(opt ...Option) options {
	opts := getDefaultOptions()
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// Option - how Options are passed as arguments.
type Option func(*options)

// options = how options are represented
type options struct {
	withPreHooks map[int]*migration.Hook
}

func getDefaultOptions() options {
	return options{}
}

// WithPreHooks provides an option to specify the set of migration hooks
// for a correspondings migration.
func WithPreHooks(h map[int]*migration.Hook) Option {
	return func(o *options) {
		o.withPreHooks = h
	}
}
