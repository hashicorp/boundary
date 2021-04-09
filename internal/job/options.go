package job

import (
	"time"
)

const defaultRunJobsLimit = 1

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
	withRunJobsLimit uint
}

func getDefaultOptions() options {
	return options{
		withRunJobsLimit: defaultRunJobsLimit,
	}
}

// WithNextRunIn provides an option to provide the duration until the next run is scheduled.
func WithNextRunIn(d time.Duration) Option {
	return func(o *options) {
		o.withNextRunIn = d
	}
}

// WithRunJobsLimit provides an option to provide the number of jobs to run.
// If WithRunJobsLimit == 0, then default run jobs limit is used.
func WithRunJobsLimit(l uint) Option {
	return func(o *options) {
		o.withRunJobsLimit = l
		if o.withRunJobsLimit == 0 {
			o.withRunJobsLimit = defaultRunJobsLimit
		}
	}
}
