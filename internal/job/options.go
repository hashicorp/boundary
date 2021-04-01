package job

import (
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	withNextScheduledRun *timestamp.Timestamp
	withJobRunStatus     string
}

func getDefaultOptions() options {
	return options{
		withNextScheduledRun: &timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{}},
		withJobRunStatus:     Running,
	}
}

// WithNextScheduledRun provides an option to provide the next scheduled run time for a job.
func WithNextScheduledRun(ts *timestamp.Timestamp) Option {
	return func(o *options) {
		o.withNextScheduledRun = ts
	}
}

// WithJobRunStatus provides an option to provide the run status for the job run.
func WithJobRunStatus(s string) Option {
	return func(o *options) {
		o.withJobRunStatus = s
	}
}
