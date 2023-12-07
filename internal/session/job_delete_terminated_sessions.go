// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package session

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type deleteTerminatedJob struct {
	repo *Repository

	// the amount of time that a session must be in the terminated
	// state for it to be deleted.
	threshold time.Duration

	// the number of sessions deleted in the most recent run
	deletedInRun int
}

func newDeleteTerminatedJob(ctx context.Context, repo *Repository, threshold time.Duration) (*deleteTerminatedJob, error) {
	const op = "session.newDeleteTerminatedJob"
	switch {
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repository")
	}

	return &deleteTerminatedJob{
		repo:      repo,
		threshold: threshold,
	}, nil
}

// Status reports the job’s current status.  The status is periodically persisted by
// the scheduler when a job is running, and will be used to verify a job is making progress.
func (d *deleteTerminatedJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: d.deletedInRun,
		Total:     d.deletedInRun,
	}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (d *deleteTerminatedJob) Run(ctx context.Context) error {
	const op = "session.(deleteTerminatedJob).Run"
	d.deletedInRun = 0
	var err error

	d.deletedInRun, err = d.repo.deleteSessionsTerminatedBefore(ctx, d.threshold)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.  This
// method is invoked after a run has successfully completed and the next run time
// is being persisted by the scheduler.  If an error is returned, the error will be logged
// but the duration returned will still be used in scheduling.  If a zero duration is returned
// the job will be scheduled to run again immediately.
func (d *deleteTerminatedJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return time.Minute * 30, nil
}

// Name is the unique name of the job.
func (d *deleteTerminatedJob) Name() string {
	return "delete_terminated_sessions"
}

// Description is the human readable description of the job.
func (d *deleteTerminatedJob) Description() string {
	return "Delete terminated sessions that were terminated "
}
