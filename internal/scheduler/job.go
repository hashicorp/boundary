// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package scheduler

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
)

// Job defines an interface for jobs that can be invoked by the scheduler.
// Multiple goroutines may invoke methods on a Job simultaneously.
type Job interface {
	// Status reports the job’s current status. It is called periodically
	// while the Run method is running and immediately after the Run method
	// completes.
	//
	// The scheduler uses the values in the returned JobStatus to verify
	// that progress is being made by the job. The scheduler will interrupt
	// the job if the values returned by Status do not change over a
	// configurable amount of time.
	//
	// See scheduler.WithInterruptThreshold for more information.
	Status() JobStatus

	// Run starts the specified job and waits for it to complete.
	//
	// The context parameter is used to notify the job that it should exit.
	//
	// The statusThreshold parameter is the amount of time the job has to
	// return a JobStatus with values different from the previous
	// JobStatus. Each time a JobStatus with values different from the
	// previous JobStatus is returned, the timer for the threshold
	// restarts. If the threshold is reached, the context is canceled.
	//
	// If the returned error is not nil, the job will be scheduled to run
	// again immediately and the returned error will be logged.
	Run(ctx context.Context, statusThreshold time.Duration) error

	// NextRunIn returns the duration the job scheduler should wait before
	// running the job again. It is only called after the Run method has
	// completed and returned a nil error. If a zero duration is returned
	// the job will be scheduled to run again immediately.
	//
	// If an error is returned, the error will be logged but the returned
	// duration will still be used in scheduling.
	NextRunIn(context.Context) (time.Duration, error)

	// Name is the unique name of the job.
	Name() string

	// Description is the human readable description of the job.
	Description() string
}

// A JobStatus represents the status of a job.
// Completed and Total are used to indicate job progress.
// The Completed value cannot be greater than the Total value
// and both values must be greater than or equal to zero.
//
// Retries is used to indicate how many times the job has retried
// accomplishing work. The value must be greater than or equal to zero.
//
// The scheduler uses the values in the JobStatus to verify that
// progress is being made by the job. The scheduler will interrupt the job
// if the values returned by Status do not change over a configurable
// amount of time.
type JobStatus struct {
	// The job's work items
	Completed int // number of items processed
	Total     int // total number of items to be processed

	// The job's liveliness
	Retries int // number of times the job has retried work
}

func validateJob(ctx context.Context, j Job) error {
	const op = "scheduler.validateJob"
	if j == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "missing job")
	}
	if j.Name() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing name")
	}
	if j.Description() == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing description")
	}
	return nil
}
