// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

const deleteTerminatedThreshold = time.Hour

// RegisterJobs registers session related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, scheduler *scheduler.Scheduler, w db.Writer, r db.Reader, k *kms.Kms, gracePeriod *atomic.Int64) error {
	const op = "session.RegisterJobs"

	if gracePeriod == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil grace period")
	}

	sessionConnectionCleanupJob, err := newSessionConnectionCleanupJob(ctx, w, gracePeriod)
	if err != nil {
		return fmt.Errorf("error creating session cleanup job: %w", err)
	}
	if err = scheduler.RegisterJob(ctx, sessionConnectionCleanupJob); err != nil {
		return fmt.Errorf("error registering session cleanup job: %w", err)
	}

	repo, err := NewRepository(ctx, r, w, k)
	if err != nil {
		return fmt.Errorf("error creating repository: %w", err)
	}
	deleteTerminatedJob, err := newDeleteTerminatedJob(ctx, repo, deleteTerminatedThreshold)
	if err != nil {
		return fmt.Errorf("error creating delete terminated session job: %w", err)
	}
	if err = scheduler.RegisterJob(ctx, deleteTerminatedJob); err != nil {
		return fmt.Errorf("error registering delete terminated session job: %w", err)
	}

	return nil
}
