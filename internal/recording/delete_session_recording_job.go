// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

const deleteSessionRecordingJobName = "delete_session_recording"

var NewDeleteSessionRecordingJobFn = newDeleteSessionRecordingJob

type deleteSessionRecordingJob struct{}

func newDeleteSessionRecordingJob(_ context.Context,
	_ db.Reader,
	_ db.Writer,
	_ globals.ControllerExtension,
	_ kms.GetWrapperer,
) (scheduler.Job, error) {
	return &deleteSessionRecordingJob{}, nil
}

// Status reports the job’s current status.
func (dsr *deleteSessionRecordingJob) Status() scheduler.JobStatus { return scheduler.JobStatus{} }

// Run performs the required work depending on the implementation.
// The context is used to notify the job that it should exit early.
func (dsr *deleteSessionRecordingJob) Run(_ context.Context, _ time.Duration) error { return nil }

// NextRunIn returns the duration until the next job run should be scheduled.
// Delete Session Recording will run every hour unless we know there are more to delete,
// then sooner
func (dsr *deleteSessionRecordingJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return 24 * time.Hour, nil
}

// Name is the unique name of the job.
func (dsr *deleteSessionRecordingJob) Name() string { return deleteSessionRecordingJobName }

// Description is the human-readable description of the job.
func (dsr *deleteSessionRecordingJob) Description() string {
	return "Manages the retention of Session Recordings in accordance with org storage policies"
}
