// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/util"
)

// SubtypeStoreService defines the interface expected
// to gather information about credential stores.
type SubtypeStoreService interface {
	ListDeletedStoreIds(context.Context, time.Time, ...Option) ([]string, error)
}

// StoreService coordinates calls across different subtype services
// to gather information about all credential stores.
type StoreService struct {
	services []SubtypeStoreService
	writer   db.Writer
}

// NewStoreService returns a new credential store service.
func NewStoreService(ctx context.Context, writer db.Writer, vaultService SubtypeStoreService, staticService SubtypeStoreService) (*StoreService, error) {
	const op = "credential.NewStoreService"
	switch {
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	case util.IsNil(vaultService):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing vault service")
	case util.IsNil(staticService):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing static service")
	}
	return &StoreService{
		services: []SubtypeStoreService{vaultService, staticService},
		writer:   writer,
	}, nil
}

func (s *StoreService) list(ctx context.Context, projectIds []string, afterItem pagination.Item, limit int) ([]Store, time.Time, error) {
	const op = "credential.(*StoreService).list"
	switch {
	case len(projectIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case limit < 1:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	var inClauses []string
	var args []any
	for i, projectId := range projectIds {
		arg := "project_id_" + strconv.Itoa(i)
		inClauses = append(inClauses, "@"+arg)
		args = append(args, sql.Named(arg, projectId))
	}
	inClause := strings.Join(inClauses, ", ")
	whereClause := "project_id in (" + inClause + ")"

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

func (s *StoreService) listRefresh(ctx context.Context, projectIds []string, updatedAfter time.Time, afterItem pagination.Item, limit int) ([]Store, time.Time, error) {
	const op = "credential.(*StoreService).list"
	switch {
	case len(projectIds) == 0:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case updatedAfter.IsZero():
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing update after time")
	case limit < 1:
		return nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	var inClauses []string
	var args []any
	for i, projectId := range projectIds {
		arg := "project_id_" + strconv.Itoa(i)
		inClauses = append(inClauses, "@"+arg)
		args = append(args, sql.Named(arg, projectId))
	}
	inClause := strings.Join(inClauses, ", ")
	whereClause := "project_id in (" + inClause + ")"

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

func (s *StoreService) queryStores(ctx context.Context, query string, args []any) ([]Store, time.Time, error) {
	const op = "credential.(*StoreService).queryStores"

	var stores []Store
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundStores []*StoreUnion
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundStores); err != nil {
				return err
			}
		}

		for _, s := range foundStores {
			subtype, err := s.storeSubtype(ctx)
			if err != nil {
				return err
			}
			stores = append(stores, subtype)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	return stores, transactionTimestamp, nil
}

func (s *StoreService) estimatedCount(ctx context.Context) (int, error) {
	const op = "credential.(*StoreService).estimatedCount"
	rows, err := s.writer.Query(ctx, estimateCountStores, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
	}
	var count int
	for rows.Next() {
		if err := s.writer.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total credential stores"))
		}
	}
	return count, nil
}
