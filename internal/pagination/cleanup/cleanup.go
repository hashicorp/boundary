// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package cleanup

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
)

// RegisterJobs registers the cleanup job for each deletion table with the provided scheduler.
func RegisterJobs(ctx context.Context, s *scheduler.Scheduler, r db.Writer, w db.Writer) error {
	const op = "cleanup.RegisterJobs"
	if s == nil {
		return errors.New(ctx, errors.InvalidParameter, "nil scheduler", op, errors.WithoutEvent())
	}
	if util.IsNil(w) {
		return errors.New(ctx, errors.Internal, "nil DB writer", op, errors.WithoutEvent())
	}

	rows, err := w.Query(ctx, selectDeletionTables, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to query for deletion tables"))
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		err = rows.Scan(&table)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for deletion tables"))
		}
		tables = append(tables, table)
	}

	for _, table := range tables {
		cleanupJob, err := newCleanupJob(ctx, w, table)
		if err != nil {
			return fmt.Errorf("error creating cleanup job: %w", err)
		}
		if err := s.RegisterJob(ctx, cleanupJob); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	return nil
}
