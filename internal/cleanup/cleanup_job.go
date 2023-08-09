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
	w db.Writer
}

func newCleanupJob(ctx context.Context, w db.Writer) (*cleanupJob, error) {
	const op = "cleanupJob.newCleanupJob"
	switch {
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	}

	return &cleanupJob{
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
	_, err := c.w.Exec(ctx, `select cleanup_deleted_tables()`, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to run sql function cleanup_deleted_tables()"))
	}
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// This job runs about once a day.
func (c *cleanupJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 24 * time.Hour, nil
}

// Name is the unique name of the job.
func (c *cleanupJob) Name() string {
	return "deleted_items_table_cleanup"
}

// Description is the human-readable description of the job.
func (c *cleanupJob) Description() string {
	return "Automatically deletes rows from the deleted items DB tables after 30 days, to ensure the tables don’t build up forever"
}
