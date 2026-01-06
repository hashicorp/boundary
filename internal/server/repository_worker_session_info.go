// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

// UpsertSessionInfo will update the session info latest request time to the current time for the given worker.
func (r *Repository) UpsertSessionInfo(ctx context.Context, workerId string, _ ...Option) error {
	const op = "server.(Repository).UpsertSessionInfo"
	if workerId == "" {
		return errors.New(ctx, errors.InvalidParameter, op, "missing worker id")
	}
	sessionInfo := NewWorkerSessionInfoRequest(workerId)
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			upsert := db.WithOnConflict(&db.OnConflict{
				Target: db.Columns{"worker_id"},
				Action: db.SetColumns([]string{"last_request_time"}),
			})
			return w.Create(ctx, sessionInfo, upsert)
		},
	)
	if err != nil {
		return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", workerId)))
	}
	return nil
}
