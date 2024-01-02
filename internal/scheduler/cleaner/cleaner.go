// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package cleaner

import (
	"context"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
)

// RegisterJob registers the cleaner job with the provided scheduler.
func RegisterJob(ctx context.Context, s *scheduler.Scheduler, w db.Writer) error {
	const op = "cleaner.RegisterJob"
	if s == nil {
		return errors.New(ctx, errors.Internal, "nil scheduler", op, errors.WithoutEvent())
	}
	if util.IsNil(w) {
		return errors.New(ctx, errors.Internal, "nil DB writer", op, errors.WithoutEvent())
	}

	if err := s.RegisterJob(ctx, newCleanerJob(w)); err != nil {
		return errors.Wrap(ctx, err, op)
	}

	return nil
}
