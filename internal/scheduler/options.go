// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import "time"

const (
	defaultRunJobsLimit       = 1
	defaultRunJobsInterval    = time.Minute
	defaultMonitorInterval    = 30 * time.Second
	defaultInterruptThreshold = 5 * time.Minute
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
	withNextRunIn          time.Duration
	withRunJobsLimit       int
	withRunJobInterval     time.Duration
	withMonitorInterval    time.Duration
	withInterruptThreshold time.Duration
	withRunNow             bool
}

func getDefaultOptions() options {
	return options{
		withRunJobsLimit:       defaultRunJobsLimit,
		withRunJobInterval:     defaultRunJobsInterval,
		withMonitorInterval:    defaultMonitorInterval,
		withInterruptThreshold: defaultInterruptThreshold,
	}
}

// WithRunJobsLimit provides an option to provide the number of jobs that will be requested
// by the scheduler when querying for jobs to run.
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

// WithRunJobsInterval provides an option to provide the interval at which the scheduler
// will query the repository for jobs to run.
// If WithRunJobsInterval == 0, then default interval is used.
func WithRunJobsInterval(l time.Duration) Option {
	return func(o *options) {
		o.withRunJobInterval = l
		if o.withRunJobInterval == 0 {
			o.withRunJobInterval = defaultRunJobsInterval
		}
	}
}

// WithMonitorInterval provides an option to provide the interval at which the scheduler
// will query running jobs for status and update the repository accordingly.
// If WithMonitorInterval == 0, then default interval is used.
func WithMonitorInterval(l time.Duration) Option {
	return func(o *options) {
		o.withMonitorInterval = l
		if o.withMonitorInterval == 0 {
			o.withMonitorInterval = defaultMonitorInterval
		}
	}
}

// WithInterruptThreshold provides an option to provide the duration after which a controller
// will interrupt a running job that is not updating its status.
// If WithInterruptThreshold == 0, then default duration is used.
func WithInterruptThreshold(l time.Duration) Option {
	return func(o *options) {
		o.withInterruptThreshold = l
		if o.withInterruptThreshold == 0 {
			o.withInterruptThreshold = defaultInterruptThreshold
		}
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

// WithRunNow provides an option to trigger the scheduling loop after updating the next run time
// of a specific job. Note this does not guarantee the job will run on the scheduler that updated
// the job run time.
func WithRunNow(b bool) Option {
	return func(o *options) {
		o.withRunNow = b
	}
}
