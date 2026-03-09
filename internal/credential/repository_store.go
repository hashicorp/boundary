// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// StoreRepository coordinates calls across different subtype services
// to gather information about all credential stores.
type StoreRepository struct {
	reader db.Reader
	writer db.Writer
}

// NewStoreRepository returns a new credential store repository.
func NewStoreRepository(ctx context.Context, reader db.Reader, writer db.Writer) (*StoreRepository, error) {
	const op = "credential.NewStoreRepository"
	switch {
	case util.IsNil(reader):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB reader")
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	}
	return &StoreRepository{
		reader: reader,
		writer: writer,
	}, nil
}

// List lists credential stores across all subtypes.
func (s *StoreRepository) List(ctx context.Context, projectIds []string, afterItem pagination.Item, limit int) ([]Store, time.Time, error) {
	const op = "credential.(*StoreRepository).list"
	switch {
	case len(projectIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case limit < 1:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	args := []any{sql.Named("project_ids", projectIds)}
	whereClause := "project_id in @project_ids"

	query := fmt.Sprintf(listStoresTemplate, whereClause, limit)
	if afterItem != nil {
		query = fmt.Sprintf(listStoresPageTemplate, whereClause, limit)
		args = append(args,
			sql.Named("last_item_create_time", afterItem.GetCreateTime()),
			sql.Named("last_item_id", afterItem.GetPublicId()),
		)
	}

	return s.queryStores(ctx, query, args)
}

// ListRefresh lists credential stores across all subtypes.
func (s *StoreRepository) ListRefresh(ctx context.Context, projectIds []string, updatedAfter time.Time, afterItem pagination.Item, limit int) ([]Store, time.Time, error) {
	const op = "credential.(*StoreRepository).list"
	switch {
	case len(projectIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	case limit < 1:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	args := []any{sql.Named("project_ids", projectIds)}
	whereClause := "project_id in @project_ids"

	query := fmt.Sprintf(listStoresRefreshTemplate, whereClause, limit)
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	)
	if afterItem != nil {
		query = fmt.Sprintf(listStoresRefreshPageTemplate, whereClause, limit)
		args = append(args,
			sql.Named("last_item_update_time", afterItem.GetUpdateTime()),
			sql.Named("last_item_id", afterItem.GetPublicId()),
		)
	}

	return s.queryStores(ctx, query, args)
}

// EstimatedCount estimates the total number of credential stores.
func (s *StoreRepository) EstimatedCount(ctx context.Context) (int, error) {
	const op = "credential.(*StoreRepository).EstimatedCount"
	rows, err := s.reader.Query(ctx, estimateCountStoresQuery, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
	}
	var count int
	for rows.Next() {
		if err := s.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
	}
	return count, nil
}

// ListDeletedIds lists the deleted IDs of all credential stores since the time specified.
func (s *StoreRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "credential.(*StoreRepository).ListDeletedIds"
	var deletedStoreIDs []string
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := w.Query(ctx, listDeletedIdsQuery, []any{sql.Named("since", since)})
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			deletedStoreIDs = append(deletedStoreIDs, id)
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return deletedStoreIDs, transactionTimestamp, nil
}

func (s *StoreRepository) queryStores(ctx context.Context, query string, args []any) ([]Store, time.Time, error) {
	const op = "credential.(*StoreRepository).queryStores"

	var stores []Store
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundStores []*StoreListQueryResult
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundStores); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}

		for _, s := range foundStores {
			store, err := s.toStore(ctx)
			if err != nil {
				return err
			}
			stores = append(stores, store)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	return stores, transactionTimestamp, nil
}
