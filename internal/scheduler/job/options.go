// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package job

import (
	"time"
)

const (
	defaultRunJobsLimit = 1
	defaultPluginId     = "pi_system"
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
	withNextRunIn    time.Duration
	withRunJobsLimit int
	withLimit        int
	withName         string
	withControllerId string
}

func getDefaultOptions() options {
	return options{
		withRunJobsLimit: defaultRunJobsLimit,
	}
}

// WithNextRunIn provides an option to provide the duration until the next run is scheduled.
// If this option is not provided the NextScheduledRun of the job will default to the
// current database time, and be available to run immediately.
func WithNextRunIn(d time.Duration) Option {
	return func(o *options) {
		o.withNextRunIn = d
	}
}

// WithRunJobsLimit provides an option to provide the number of jobs to run.
// If WithRunJobsLimit == 0, then default run jobs limit is used.
// If WithRunJobsLimit < 0, then no limit is used.
func WithRunJobsLimit(l int) Option {
	return func(o *options) {
		o.withRunJobsLimit = l
		if o.withRunJobsLimit == 0 {
			o.withRunJobsLimit = defaultRunJobsLimit
		}
	}
}

// WithLimit provides an option to provide a limit for ListJobs. Intentionally
// allowing negative integers. If WithLimit < 0, then unlimited results are
// returned. If WithLimit == 0, then default limits are used for results.
func WithLimit(l int) Option {
	return func(o *options) {
		o.withLimit = l
	}
}

// WithName provides an option to provide the name to match when calling ListJobs
func WithName(n string) Option {
	return func(o *options) {
		o.withName = n
	}
}

// WithControllerId provides an option to provide the server id to match when calling InterruptRuns
func WithControllerId(id string) Option {
	return func(o *options) {
		o.withControllerId = id
	}
}
