// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
)

func (r *Repository) ListControllers(ctx context.Context, opt ...Option) ([]*Controller, error) {
	return r.listControllersWithReader(ctx, r.reader, opt...)
}

// listControllersWithReader will return a listing of resources and honor the
// WithLimit option or the repo defaultLimit. It accepts a reader, allowing it
// to be used within a transaction or without.
func (r *Repository) listControllersWithReader(ctx context.Context, reader db.Reader, opt ...Option) ([]*Controller, error) {
	opts := GetOpts(opt...)
	liveness := opts.withLiveness
	if liveness == 0 {
		liveness = DefaultLiveness
	}
	var where string
	if liveness > 0 {
		where = fmt.Sprintf("update_time > now() - interval '%d seconds'", uint32(liveness.Seconds()))
	}
	var controllers []*Controller
	if err := reader.SearchWhere(
		ctx,
		&controllers,
		where,
		[]any{},
		db.WithLimit(-1),
	); err != nil {
		return nil, errors.Wrap(ctx, err, "workers.listControllersWithReader")
	}
	return controllers, nil
}

func (r *Repository) UpsertController(ctx context.Context, controller *Controller) (int, error) {
	const op = "server.(Repository).UpsertController"
	if controller == nil {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "controller is nil")
	}
	var rowsUpdated int64
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(read db.Reader, w db.Writer) error {
			var err error
			onConflict := &db.OnConflict{
				Target: db.Columns{"private_id"},
				Action: append(db.SetColumns([]string{"description", "address"}), db.SetColumnValues(map[string]any{"update_time": "now()"})...),
			}
			err = w.Create(ctx, controller, db.WithOnConflict(onConflict), db.WithReturnRowsAffected(&rowsUpdated))
			if err != nil {
				return errors.Wrap(ctx, err, op+":Upsert")
			}
			return nil
		},
	)
	if err != nil {
		return db.NoRowsAffected, err
	}

	return int(rowsUpdated), nil
}

// UpdateControllerStatus updates the controller's status in the repository.
// This includes updating the address or description of the controller as well
// as updating the update_time attribute, which is required for liveness checks
// as part of a controller's status ticking.
func (r *Repository) UpdateControllerStatus(ctx context.Context, controller *Controller) (int, error) {
	const op = "server.(Repository).UpdateControllerStatus"

	if controller == nil {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "controller is nil")
	}
	if controller.PrivateId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "controller private_id is empty")
	}
	if controller.Address == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "controller address is empty")
	}

	var rowsUpdated int
	_, err := r.writer.DoTx(
		ctx,
		db.StdRetryCnt,
		db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			var err error
			params := []any{
				sql.Named("controller_private_id", controller.PrivateId),
				sql.Named("controller_address", controller.Address),
			}

			if controller.Description != "" {
				params = append(params, sql.Named("controller_description", controller.Description))
			} else {
				params = append(params, sql.Named("controller_description", nil))
			}

			rowsUpdated, err = w.Exec(ctx, updateController, params)
			switch {
			case err != nil:
				return errors.Wrap(ctx, err, op+":Update")
			case rowsUpdated > 1:
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 resource would have been updated")
			case rowsUpdated == 0:
				return errors.New(ctx, errors.RecordNotFound, op, "no resources would have been updated")
			default:
				return nil
			}
		},
	)
	if err != nil {
		return db.NoRowsAffected, err
	}

	return rowsUpdated, nil
}
