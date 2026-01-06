// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package helper

import "github.com/hashicorp/boundary/api/targets"

// getOpts iterates the inbound Options and returns a struct and any errors
func getOpts(opt ...Option) (*Options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}

	}
	return opts, nil
}

// Options contains various options. The values are exported since the options
// are parsed in various other packages.
type Options struct {
	WithSkipSessionTeardown bool
	WithWorkerInfo          []*targets.WorkerInfo
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{}
}

// WithSkipSessionTeardown can be used to override the normal behavior of the
// session sending a teardown request to the worker on completion. This is
// useful if you know that this will result in an error (for instance, if the
// worker is going to be offline) and want to avoid the attempted connection or
// avoid the error rather than ignore it.
func WithSkipSessionTeardown(with bool) Option {
	return func(o *Options) error {
		o.WithSkipSessionTeardown = with
		return nil
	}
}

// WithWorkerInfo can be used to override the default worker address localhost:9202
// for SessionAuthroizationData. This is useful when testing session connection with
// dev workers that are not utilizing default addresses.
func WithWorkerInfo(workerInfo []*targets.WorkerInfo) Option {
	return func(o *Options) error {
		o.WithWorkerInfo = workerInfo
		return nil
	}
}
