package job

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

// Option - how Options are passed as arguments
type Option func(*options)

// options = how options are represented
type options struct {
	withNextScheduledRun time.Time
	withStatus           Status
}

func getDefaultOptions() options {
	return options{
		withNextScheduledRun: time.Unix(0, 0),
		withStatus:           Running,
	}
}

// WithNextScheduledRun provides an option to provide the next scheduled run time for a job.
func WithNextScheduledRun(ts time.Time) Option {
	return func(o *options) {
		o.withNextScheduledRun = ts
	}
}

// WithStatus provides an option to provide the run status for the job run.
func WithStatus(s Status) Option {
	return func(o *options) {
		o.withStatus = s
	}
}
