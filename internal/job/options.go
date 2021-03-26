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
	withLimit            int
	withNextScheduledRun *timestamp.Timestamp
	withJobRunStatus     RunStatus
}

func getDefaultOptions() options {
	return options{
		withLimit:            0,
		withNextScheduledRun: &timestamp.Timestamp{Timestamp: &timestamppb.Timestamp{}},
		withJobRunStatus:     Running,
	}
}

// WithLimit provides an option to provide a limit.  Intentionally allowing
// negative integers.   If WithLimit < 0, then unlimited results are returned.
// If WithLimit == 0, then default limits are used for results.
func WithLimit(limit int) Option {
	return func(o *options) {
		o.withLimit = limit
	}
}

// WithNextScheduledRun provides an option to provide the next scheduled run time for a job.
func WithNextScheduledRun(ts *timestamp.Timestamp) Option {
	return func(o *options) {
		o.withNextScheduledRun = ts
	}
}

// WithJobRunStatus provides an option to provide the run status for the job run.
func WithJobRunStatus(s RunStatus) Option {
	return func(o *options) {
		o.withJobRunStatus = s
	}
}
