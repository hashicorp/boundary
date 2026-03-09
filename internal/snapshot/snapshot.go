// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package snapshot

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
)

// RegisterJob registers the snapshot job with the provided scheduler.
func RegisterJob(ctx context.Context, s *scheduler.Scheduler, r db.Reader, w db.Writer) error {
	const op = "snapshot.RegisterJob"
	if s == nil {
		return errors.New(ctx, errors.InvalidParameter, "nil scheduler", op, errors.WithoutEvent())
	}
	if util.IsNil(r) {
		return errors.New(ctx, errors.Internal, "nil DB reader", op, errors.WithoutEvent())
	}
	if util.IsNil(w) {
		return errors.New(ctx, errors.Internal, "nil DB writer", op, errors.WithoutEvent())
	}

	snapshotJob, err := newSnapshotJob(ctx, r, w)
	if err != nil {
		return fmt.Errorf("error creating snapshot job: %w", err)
	}
	if err := s.RegisterJob(ctx, snapshotJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
