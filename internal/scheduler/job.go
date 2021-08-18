package scheduler

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

// Job defines an interface for jobs that can be invoked by the scheduler.
type Job interface {
	// Status reports the job’s current status.  The status is periodically persisted by
	// the scheduler when a job is running, and will be used to verify a job is making progress.
	Status() JobStatus

	// Run performs the required work depending on the implementation.
	// The context is used to notify the job that it should exit early.
	Run(ctx context.Context) error

	// NextRunIn returns the duration until the next job run should be scheduled.  This
	// method is invoked after a run has successfully completed and the next run time
	// is being persisted by the scheduler.  If an error is returned, the error will be logged
	// but the duration returned will still be used in scheduling.  If a zero duration is returned
	// the job will be scheduled to run again immediately.
	NextRunIn() (time.Duration, error)

	// Name is the unique name of the job.
	Name() string

	// Description is the human readable description of the job.
	Description() string
}

// JobStatus defines the struct that must be returned by the Job.Status() method.
type JobStatus struct {
	// Completed and Total are used to indicate job progress,
	// each job implementation will determine the definition of
	// progress by calculating both Completed and Total.
	Completed, Total int
}

func validateJob(j Job) error {
	const op = "scheduler.validateJob"
	if j == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing job")
	}
	if j.Name() == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing name")
	}
	if j.Description() == "" {
		return errors.NewDeprecated(errors.InvalidParameter, op, "missing description")
	}
	return nil
}
