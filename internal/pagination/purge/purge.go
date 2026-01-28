// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package purge implements a scheduler job used to purge old
// rows from the deleted IDs tables kept for pagination purposes.
package purge

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/util"
)

// RegisterJobs registers the purge job for each deletion table with the provided scheduler.
func RegisterJobs(ctx context.Context, s *scheduler.Scheduler, r db.Reader, w db.Writer) error {
	const op = "purge.RegisterJobs"
	if s == nil {
		return errors.New(ctx, errors.InvalidParameter, "nil scheduler", op, errors.WithoutEvent())
	}
	if util.IsNil(r) {
		return errors.New(ctx, errors.Internal, "nil DB reader", op, errors.WithoutEvent())
	}
	if util.IsNil(w) {
		return errors.New(ctx, errors.Internal, "nil DB writer", op, errors.WithoutEvent())
	}

	rows, err := r.Query(ctx, getDeletionTablesQuery, nil)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to query for deletion tables"))
	}
	defer rows.Close()

	for rows.Next() {
		var table string
		err = rows.Scan(&table)
		if err != nil {
			return errors.Wrap(ctx, err, op, errors.WithMsg("unable to scan rows for deletion tables"))
		}

		purgeJob, err := newPurgeJob(ctx, w, table)
		if err != nil {
			return fmt.Errorf("error creating purge job: %w", err)
		}
		if err := s.RegisterJob(ctx, purgeJob); err != nil {
			return errors.Wrap(ctx, err, op)
		}
	}
	if err := rows.Err(); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get next row for deletion tables"))
	}
	return nil
}
