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
	withNextRunAt    time.Time
	withStatus       Status
	withRunJobsLimit uint
}

func getDefaultOptions() options {
	return options{
		withNextRunAt:    time.Unix(0, 0),
		withStatus:       Running,
		withRunJobsLimit: defaultRunJobsLimit,
	}
}

// WithNextRunAt provides an option to provide the next scheduled run time for a job.
func WithNextRunAt(ts time.Time) Option {
	return func(o *options) {
		o.withNextRunAt = ts
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

// WithStatus provides an option to provide the run status for the job run.
func WithStatus(s Status) Option {
	return func(o *options) {
		o.withStatus = s
	}
}
