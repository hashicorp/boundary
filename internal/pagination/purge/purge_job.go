// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package purge

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

type purgeJob struct {
	w     db.Writer
	table string
}

func newPurgeJob(ctx context.Context, w db.Writer, table string) (*purgeJob, error) {
	const op = "purgeJob.newPurgeJob"
	switch {
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case table == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing table")
	}

	return &purgeJob{
		w:     w,
		table: table,
	}, nil
}

// Status reports the job’s current status.
func (c *purgeJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (c *purgeJob) Run(ctx context.Context) error {
	const op = "purge.(purgeJob).Run"
	_, err := c.w.Exec(ctx, fmt.Sprintf(purgeExpiredRows, c.table), nil)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to prune table %s", c.table)))
	}
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// This job runs about once a day.
func (c *purgeJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 24 * time.Hour, nil
}

// Name is the unique name of the job.
func (c *purgeJob) Name() string {
	return "deleted_items_table_purge"
}

// Description is the human-readable description of the job.
func (c *purgeJob) Description() string {
	return "Automatically deletes rows from the deleted items DB tables after 30 days, to ensure the tables don’t build up forever"
}
