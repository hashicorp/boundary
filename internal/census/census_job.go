// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package census

import (
	"context"
	"io"
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
	r                db.Reader
	w                db.Writer
	lurEnabled       bool
	emitEvents       bool
	sessionsAgent    any
	activeUsersAgent any
	eventCtx         context.Context
	randReader       io.Reader
}

func newCensusJob(ctx context.Context, lurEnabled bool, r db.Reader, w db.Writer, randomReader io.Reader) (*censusJob, error) {
	const op = "censusJob.newCensusJob"
	switch {
	case r == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	}

	return &censusJob{
		r:                r,
		w:                w,
		lurEnabled:       lurEnabled,
		emitEvents:       false,
		sessionsAgent:    nil,
		activeUsersAgent: nil,
		eventCtx:         ctx,
		randReader:       randomReader,
	}, nil
}

// Status reports the job’s current status.
func (c *censusJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{}
}

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (c *censusJob) Run(ctx context.Context, _ time.Duration) error {
	err := RunFn(ctx, c)
	return err
}

func runInternal(ctx context.Context, c *censusJob) error {
	return nil
}

// NextRunIn returns the duration until the next job run should be scheduled.
// Census will run every hour to ensure any interrupted jobs will be re-attempted
func (c *censusJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return time.Hour, nil
}

// Name is the unique name of the job.
func (c *censusJob) Name() string {
	return "job_run_census"
}

// Description is the human-readable description of the job.
func (c *censusJob) Description() string {
	return "Gathers and exports session usage metrics"
}
