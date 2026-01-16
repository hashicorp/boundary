// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package snapshot

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

var runFn = runInternal

type snapshotJob struct {
	r db.Reader
	w db.Writer
}

func newSnapshotJob(ctx context.Context, r db.Reader, w db.Writer) (*snapshotJob, error) {
	const op = "snapshotJob.newSnapshotJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	}

	return &snapshotJob{
		r: r,
		w: w,
	}, nil
}

// Status reports the job’s current status.
func (c *snapshotJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (c *snapshotJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "snapshot.(snapshotJob).Run"
	err := runFn(ctx, c)
	return err
}

func runInternal(ctx context.Context, c *snapshotJob) error {
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We report as ready immediately after a successful run. This doesn't mean that
// this job will run immediately, only about as often as the configured scheduler interval.
func (c *snapshotJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 0, nil
}

// Name is the unique name of the job.
func (c *snapshotJob) Name() string {
	return "job_run_snapshot"
}

// Description is the human-readable description of the job.
func (c *snapshotJob) Description() string {
	return "Creates and stores a snapshot from sessions warehouse to snapshot table"
}
