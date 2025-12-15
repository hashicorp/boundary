// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package servers

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/nodeenrollment"
)

// rotateRootsJob defines a periodic job that initiates root certificate rotation
// It runs every hour; the root rotation function in the library is designed to not
// do anything if it's not time to rotate (roots are within their valid ranges)
type rotateRootsJob struct {
	workerAuthRepo *server.WorkerAuthRepositoryStorage

	totalRotates int

	rotateFrequency time.Duration

	certificateLifetime time.Duration
}

// newRotateRootsJob instantiates the rotate roots job.
func newRotateRootsJob(ctx context.Context, r db.Reader, w db.Writer, kms *kms.Kms, opt ...Option) (*rotateRootsJob, error) {
	const op = "server.newRotateRootsJob"
	switch {
	case isNil(r):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing reader")
	case isNil(w):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing writer")
	case kms == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	workerAuthRepo, err := server.NewRepositoryStorage(ctx, r, w, kms)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	opts := getOpts(opt...)

	return &rotateRootsJob{
		workerAuthRepo:      workerAuthRepo,
		totalRotates:        0,
		rotateFrequency:     opts.withRotationFrequency,
		certificateLifetime: opts.withCertificateLifetime,
	}, nil
}

// Name returns a short, unique name for the job.
func (r *rotateRootsJob) Name() string { return "rotate_roots" }

// Description returns the description for the job.
func (r *rotateRootsJob) Description() string {
	return "Rotate root certificates"
}

// NextRunIn returns the next run time after a job is completed.
// This is represented by RotateFrequency
func (r *rotateRootsJob) NextRunIn(_ context.Context) (time.Duration, error) {
	return r.rotateFrequency, nil
}

// Status returns the status of the running job.
func (r *rotateRootsJob) Status() scheduler.JobStatus {
	return scheduler.JobStatus{
		Completed: r.totalRotates,
		Total:     r.totalRotates,
	}
}

// Run executes the job by calling the rotateRoots domain function
func (r *rotateRootsJob) Run(ctx context.Context, _ time.Duration) error {
	const op = "server.(rotateRootsJob).Run"

	_, err := server.RotateRoots(ctx, r.workerAuthRepo, nodeenrollment.WithCertificateLifetime(r.certificateLifetime))
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}

	r.totalRotates += 1

	return nil
}
