// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package cleaner

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type cleanerJob struct {
	w db.Writer
}

func newCleanerJob(w db.Writer) *cleanerJob {
	return &cleanerJob{
		w: w,
	}
}

// Status reports the job’s current status.
func (c *cleanerJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (c *cleanerJob) Run(ctx context.Context) error {
	const op = "cleaner.(cleanerJob).Run"

	if _, err := c.w.Exec(ctx, "delete from job_run where status='completed'", nil); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We report as ready immediately after a successful run. This doesn't mean that
// this job will run immediately, only about as often as the configured scheduler interval.
func (c *cleanerJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 0, nil
}

// Name is the unique name of the job.
func (c *cleanerJob) Name() string {
	return "job_run_cleaner"
}

// Description is the human readable description of the job.
func (c *cleanerJob) Description() string {
	return "Cleans completed job runs"
}
