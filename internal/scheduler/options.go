package scheduler

import "time"

const (
	defaultRunJobsLimit    = 1
	defaultRunJobsInterval = time.Minute
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
	withRunJobsLimit   uint
	withRunJobInterval time.Duration
}

func getDefaultOptions() options {
	return options{
		withRunJobsLimit:   defaultRunJobsLimit,
		withRunJobInterval: defaultRunJobsInterval,
	}
}

// WithRunJobsLimit provides an option to provide the number of jobs that will be requested
// by the scheduler when querying for jobs to run.
// If WithRunJobsLimit == 0, then default run jobs limit is used.
func WithRunJobsLimit(l uint) Option {
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
