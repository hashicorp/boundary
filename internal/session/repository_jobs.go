// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package session

import (
	"context"
	"database/sql"
	"time"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
)

type deleteJobParams struct {
	TotalToDelete   int
	BatchSize       int
	WindowStartTime *timestamp.Timestamp
}

func (r *Repository) getDeleteJobParams(ctx context.Context, threshold time.Duration) (deleteJobParams, error) {
	const op = "session.(Repository).getDeleteJobParams"

	args := []any{
		sql.Named("threshold_seconds", threshold.Seconds()),
	}
	rows, err := r.reader.Query(ctx, getDeleteJobParams, args)
	if err != nil {
		return deleteJobParams{}, errors.Wrap(ctx, err, op, errors.WithMsg("error getting parameters for delete terminated sessions job"))
	}
	defer rows.Close()

	var jobParams deleteJobParams
	for rows.Next() {
		if err := r.reader.ScanRows(ctx, rows, &jobParams); err != nil {
			return deleteJobParams{}, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
	}
	if err := rows.Err(); err != nil {
		return deleteJobParams{}, errors.Wrap(ctx, err, op, errors.WithMsg("next row failed"))
	}
	return jobParams, nil
}

func (r *Repository) setDeleteJobBatchSize(ctx context.Context, batchSize int) error {
	const op = "session.(Repository).setDeleteJobBatchSize"

	args := []any{
		sql.Named("batch_size", batchSize),
	}

	_, err := r.writer.Exec(ctx, setDeleteJobBatchSize, args)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg("error setting delete job batch size"))
	}
	return nil
}

func (r *Repository) deleteTerminatedSessionsBatch(ctx context.Context, terminatedBefore *timestamp.Timestamp, batchSize int) (int, error) {
	const op = "session.(Repository).deleteTerminatedSessionsBatch"

	args := []any{
		sql.Named("terminated_before", terminatedBefore),
		sql.Named("batch_size", batchSize),
	}

	c, err := r.writer.Exec(ctx, deleteTerminatedInBatch, args)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("error deleting terminated sessions"))
	}
	return c, nil
}
