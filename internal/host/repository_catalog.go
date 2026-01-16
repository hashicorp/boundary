// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/util"
)

// CatalogRepository coordinates calls across different subtype services
// to gather information about all host catalogs.
type CatalogRepository struct {
	reader db.Reader
	writer db.Writer
}

// NewCatalogRepository returns a new host catalog repository.
func NewCatalogRepository(ctx context.Context, reader db.Reader, writer db.Writer) (*CatalogRepository, error) {
	const op = "host.NewCatalogRepository"
	switch {
	case util.IsNil(reader):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB reader")
	case util.IsNil(writer):
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing DB writer")
	}
	return &CatalogRepository{
		reader: reader,
		writer: writer,
	}, nil
}

// List lists host catalogs across all subtypes.
func (s *CatalogRepository) List(ctx context.Context, projectIds []string, afterItem pagination.Item, limit int) ([]Catalog, []*plugin.Plugin, time.Time, error) {
	const op = "host.(*CatalogRepository).list"
	switch {
	case len(projectIds) == 0:
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case limit < 1:
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	args := []any{sql.Named("project_ids", projectIds)}
	whereClause := "project_id in @project_ids"

	query := fmt.Sprintf(listCatalogsTemplate, whereClause, limit)
	if afterItem != nil {
		query = fmt.Sprintf(listCatalogsPageTemplate, whereClause, limit)
		args = append(args,
			sql.Named("last_item_create_time", afterItem.GetCreateTime()),
			sql.Named("last_item_id", afterItem.GetPublicId()),
		)
	}

	return s.queryCatalogs(ctx, query, args)
}

// ListRefresh lists host catalogs across all subtypes.
func (s *CatalogRepository) ListRefresh(ctx context.Context, projectIds []string, updatedAfter time.Time, afterItem pagination.Item, limit int) ([]Catalog, []*plugin.Plugin, time.Time, error) {
	const op = "host.(*CatalogRepository).list"
	switch {
	case len(projectIds) == 0:
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case updatedAfter.IsZero():
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing updated after time")
	case limit < 1:
		return nil, nil, time.Time{}, errors.New(ctx, errors.InvalidParameter, op, "missing limit")
	}

	args := []any{sql.Named("project_ids", projectIds)}
	whereClause := "project_id in @project_ids"

	query := fmt.Sprintf(listCatalogsRefreshTemplate, whereClause, limit)
	args = append(args,
		sql.Named("updated_after_time", timestamp.New(updatedAfter)),
	)
	if afterItem != nil {
		query = fmt.Sprintf(listCatalogsRefreshPageTemplate, whereClause, limit)
		args = append(args,
			sql.Named("last_item_update_time", afterItem.GetUpdateTime()),
			sql.Named("last_item_id", afterItem.GetPublicId()),
		)
	}

	return s.queryCatalogs(ctx, query, args)
}

// EstimatedCount estimates the total number of host catalogs.
func (s *CatalogRepository) EstimatedCount(ctx context.Context) (int, error) {
	const op = "host.(*CatalogRepository).EstimatedCount"
	rows, err := s.reader.Query(ctx, estimateCountCatalogsQuery, nil)
	if err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total host catalogs"))
	}
	var count int
	for rows.Next() {
		if err := s.reader.ScanRows(ctx, rows, &count); err != nil {
			return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total host catalogs"))
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errors.Wrap(ctx, err, op, errors.WithMsg("failed to query total host catalogs"))
	}
	return count, nil
}

// ListDeletedIds lists the deleted IDs of all host catalogs since the time specified.
func (s *CatalogRepository) ListDeletedIds(ctx context.Context, since time.Time) ([]string, time.Time, error) {
	const op = "host.(*CatalogRepository).ListDeletedIds"
	var deletedCatalogIDs []string
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
			deletedCatalogIDs = append(deletedCatalogIDs, id)
		}
		if err := rows.Err(); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return deletedCatalogIDs, transactionTimestamp, nil
}

func (s *CatalogRepository) queryCatalogs(ctx context.Context, query string, args []any) ([]Catalog, []*plugin.Plugin, time.Time, error) {
	const op = "host.(*CatalogRepository).queryCatalogs"

	var catalogs []Catalog
	var plugins []*plugin.Plugin
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		rows, err := r.Query(ctx, query, args)
		if err != nil {
			return err
		}
		defer rows.Close()
		var foundCatalogs []*CatalogListQueryResult
		for rows.Next() {
			if err := r.ScanRows(ctx, rows, &foundCatalogs); err != nil {
				return err
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		var plgIds []string
		for _, c := range foundCatalogs {
			catalog, err := c.toCatalog(ctx)
			if err != nil {
				return err
			}
			catalogs = append(catalogs, catalog)
			if c.PluginId != "" {
				plgIds = append(plgIds, c.PluginId)
			}
		}
		if err := r.SearchWhere(ctx, &plugins, "public_id in (?)", []any{plgIds}); err != nil {
			return errors.Wrap(ctx, err, op)
		}
		transactionTimestamp, err = r.Now(ctx)
		return err
	}); err != nil {
		return nil, nil, time.Time{}, errors.Wrap(ctx, err, op)
	}

	return catalogs, plugins, transactionTimestamp, nil
}
