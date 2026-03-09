// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package schema

import "github.com/hashicorp/boundary/internal/db/schema/internal/edition"

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
	withEditions         edition.Editions
	withDeleteLog        bool
	withRepairMigrations map[string]map[int]bool
}

func getDefaultOptions() options {
	return options{}
}

// WithEditions provides an optional migration states.
func WithEditions(editions edition.Editions) Option {
	return func(o *options) {
		o.withEditions = editions
	}
}

// WithDeleteLog provides an option to specify the deletion of log entries.
func WithDeleteLog(del bool) Option {
	return func(o *options) {
		o.withDeleteLog = del
	}
}

// WithRepairMigrations provides an option to specify the set of migrations
// that should run their repair functions if there is a failure on a prehook check.
func WithRepairMigrations(r RepairMigrations) Option {
	return func(o *options) {
		o.withRepairMigrations = r
	}
}
