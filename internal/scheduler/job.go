package scheduler

import (
	"context"
	"time"
)

// JobId is the unique id assigned to the job after registration, it is generated and
// returned by RegisterJob.  The id is predictable and uses the job code and name as a seed.
// This id is prefixed with "job_".
type JobId string

// Job defines an interface for jobs that can will be invoked by the scheduler.
type Job interface {
	// Status reports the job’s current status.  The status is periodically persisted by
	// the scheduler when a job is running, and will be used to verify a job is making progress.
	Status() JobStatus

	// Run performs the required work depending on the implementation.
	// The context is used to notify the job that it should exit early.
	Run(ctx context.Context) error

	// NextRunIn returns the duration until the next job run should be scheduled.  This
	// method is invoked after a run has successfully completed and the next run time
	// is being persisted by the scheduler.
	NextRunIn() time.Duration

	// Name is the human readable name of the job.
	Name() string

	// Description is the human readable description of the job.
	Description() string
}

// JobStatus defines the struct that must be returned by the Job.Status() method.
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
