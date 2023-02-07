// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package job

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
)

// RegisterJobs registers kms related jobs with the provided scheduler.
func RegisterJobs(ctx context.Context, s *scheduler.Scheduler, kmsRepo *kms.Kms) error {
	const op = "kmsjob.RegisterJobs"
	if s == nil {
		return errors.New(ctx, errors.Internal, "nil scheduler", op, errors.WithoutEvent())
	}
	if kmsRepo == nil {
		return errors.New(ctx, errors.Internal, "nil kms repo", op, errors.WithoutEvent())
	}

	dataKeyVersionDestructionMonitorJob, err := newDataKeyVersionDestructionMonitorJob(ctx, kmsRepo)
	if err != nil {
		return errors.Wrap(ctx, err, op)
	}
	if err := s.RegisterJob(ctx, dataKeyVersionDestructionMonitorJob); err != nil {
		return errors.Wrap(ctx, err, op)
	}
	for _, tableName := range kms.ListTablesSupportingRewrap() {
		tableRewrappingJob, err := newTableRewrappingJob(ctx, kmsRepo, tableName)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		if err := s.RegisterJob(ctx, tableRewrappingJob); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}

	return nil
}
