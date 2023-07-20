// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cleanup

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type cleanupJob struct {
	r db.Reader
	w db.Writer
}

func newCleanupJob(ctx context.Context, r db.Reader, w db.Writer) (*cleanupJob, error) {
	const op = "cleanupJob.newCleanupJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	}

	return &cleanupJob{
		r: r,
		w: w,
	}, nil
}

// Status reports the job’s current status.
func (c *cleanupJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (c *cleanupJob) Run(ctx context.Context) error {
	const op = "cleanup.(cleanupJob).Run"
	if _, err := c.w.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			_, err := w.Exec(ctx, `delete from target_deleted where delete_time < now() - interval '30 days'`, nil)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete from target_deleted table"))
			}
			return nil
		},
	); err != nil {
		// already wrapped
		return err
	}
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We report as ready immediately after a successful run. This doesn't mean that
// this job will run immediately, only about as often as the configured scheduler interval.
func (c *cleanupJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 0, nil
}

// Name is the unique name of the job.
func (c *cleanupJob) Name() string {
	return "job_run_cleanup"
}

// Description is the human-readable description of the job.
func (c *cleanupJob) Description() string {
	return "Automatically deletes rows from the deleted items DB table(s) after 30 days, to ensure the tables don’t build up forever"
}
