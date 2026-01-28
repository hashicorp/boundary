// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package servers

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
)

var NewUpsertWorkerStorageBucketJobFn = newUpsertWorkerStorageBucketJob

type upsertWorkerStorageBucketJob struct{}

func newUpsertWorkerStorageBucketJob(_ context.Context,
	_ db.Reader,
	_ db.Writer,
	_ *kms.Kms,
	_ globals.ControllerExtension,
	_ *atomic.Int64,
	_ *scheduler.Scheduler,
) (scheduler.Job, error) {
	return &upsertWorkerStorageBucketJob{}, nil
}

// Status reports the job’s current status.
func (usb *upsertWorkerStorageBucketJob) Status() scheduler.JobStatus { return scheduler.JobStatus{} }

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (usb *upsertWorkerStorageBucketJob) Run(ctx context.Context, _ time.Duration) error { return nil }

// NextRunIn returns the duration until the next job run should be scheduled.
// Upsert Worker Storage Bucket will run every 24 hours unless we know there are
// more to storage buckets to upserted, then sooner
func (usb *upsertWorkerStorageBucketJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 24 * time.Hour, nil
}

// Name is the unique name of the job.
func (usb *upsertWorkerStorageBucketJob) Name() string {
	return server.UpsertWorkerStorageBucketJobName
}

// Description is the human-readable description of the job.
func (usb *upsertWorkerStorageBucketJob) Description() string {
	return "Upserts storage buckets of workers that are out of date with the latest storage bucket version. " +
		"This ensures active workers that are using outdated storage buckets are updated to the latest version."
}
