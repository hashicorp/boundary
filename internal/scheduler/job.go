package scheduler

import (
	"context"
	"time"
)

// Job TODO (lruch): add doc
type Job interface {
	// Status reports the job’s current status.
	Status() JobStatus

	// Run performs the required work depending on the
	// implementation.
	// The context is used to notify the job that it
	// should exit early.
	Run(ctx context.Context) error

	// NextRunIn returns the duration until the next job
	// run should be scheduled.
	NextRunIn() time.Duration

	// Name is the human readable name of the job
	Name() string

	// Description is the human readable description of the job
	Description() string
}

// JobStatus TODO (lruch): add doc
type JobStatus struct {
	// Running indicates if the job is currently running or not
	Running bool

	// Runtime indicates how long the job has been running
	Runtime time.Duration

	// Completed and Total are used to indicate job progress,
	// each job implementation will determine the definition of
	// progress by calculating both Completed and Total.
	Completed, Total int
}
