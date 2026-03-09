// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// RegisterJob registers the delete session recording job with the provided scheduler.
func RegisterJob(ctx context.Context,
	s *scheduler.Scheduler,
	r db.Reader,
	w db.Writer,
	controllerExt globals.ControllerExtension,
	kms kms.GetWrapperer,
) error {
	const op = "storage.RegisterJob"
	switch {
	case s == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing scheduler")
	case r == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing db.Reader")
	case w == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing db.Writer")
	case kms == nil:
		return errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}

	dsrJob, err := NewDeleteSessionRecordingJobFn(ctx, r, w, controllerExt, kms)
	if err != nil {
		return fmt.Errorf("error creating delete session recording job: %w", err)
	}
	if err := s.RegisterJob(ctx, dsrJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
