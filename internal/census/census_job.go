// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package census

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
)

var (
	NewCensusJobFn = newCensusJob
	RunFn          = runInternal
)

type censusJob struct {
	r        db.Reader
	w        db.Writer
	optOut   bool
	agent    any
	eventCtx context.Context
}

func newCensusJob(ctx context.Context, optOut bool, r db.Reader, w db.Writer) (*censusJob, error) {
	const op = "censusJob.newCensusJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	}

	return &censusJob{
		r:        r,
		w:        w,
		optOut:   optOut,
		agent:    nil,
		eventCtx: ctx,
	}, nil
}

// Status reports the job’s current status.
func (c *censusJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (c *censusJob) Run(ctx context.Context) error {
	const op = "census.(censusJob).Run"
	err := RunFn(ctx, c)
	return err
}

func runInternal(ctx context.Context, c *censusJob) error {
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// We report as ready immediately after a successful run. This doesn't mean that
// this job will run immediately, only about as often as the configured scheduler interval.
func (c *censusJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 0, nil
}

// Name is the unique name of the job.
func (c *censusJob) Name() string {
	return "job_run_census"
}

// Description is the human-readable description of the job.
func (c *censusJob) Description() string {
	return "Gathers and exports session usage metrics"
}
