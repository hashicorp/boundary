// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package billing

import (
	"time"
)

// getOpts - iterate the inbound Options and return a struct
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
	withStartTime *time.Time
	withEndTime   *time.Time
}

func getDefaultOptions() options {
	return options{
		withStartTime: nil,
		withEndTime:   nil,
	}
}

// WithStartTime allows setting the start time for the query.
func WithStartTime(startTime *time.Time) Option {
	return func(o *options) {
		o.withStartTime = startTime
	}
}

// WithEndTime allows setting the end time for the query.
func WithEndTime(endTime *time.Time) Option {
	return func(o *options) {
		o.withEndTime = endTime
	}
}
