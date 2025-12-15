// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package census

import (
	"context"
	"fmt"
	"io"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
)

// RegisterJob registers the census job with the provided scheduler.
func RegisterJob(ctx context.Context, s *scheduler.Scheduler, lurEnabled bool, r db.Reader, w db.Writer, randomReader io.Reader) error {
	const op = "census.RegisterJob"
	if s == nil {
		return errors.New(ctx, errors.InvalidParameter, "nil scheduler", op, errors.WithoutEvent())
	}
	if util.IsNil(r) {
		return errors.New(ctx, errors.Internal, "nil DB reader", op, errors.WithoutEvent())
	}
	if util.IsNil(w) {
		return errors.New(ctx, errors.Internal, "nil DB writer", op, errors.WithoutEvent())
	}

	censusJob, err := NewCensusJobFn(ctx, lurEnabled, r, w, randomReader)
	if err != nil {
		return fmt.Errorf("error creating census job: %w", err)
	}
	if err := s.RegisterJob(ctx, censusJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
