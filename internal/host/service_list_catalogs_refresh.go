// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists host catalogs according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned catalogs.
func (s *CatalogService) ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterCatalogFunc,
	tok *refreshtoken.Token,
	projectIds []string,
) (*pagination.ListResponse[Catalog], []*plugin.Plugin, error) {
	const op = "host.(*CatalogService).ListRefresh"

	if len(grantsHash) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if tok == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}
	if len(projectIds) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	}

	var plgs []*plugin.Plugin
	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem Catalog, limit int) ([]Catalog, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			opts = append(opts, WithStartPageAfterItem(tok.LastItem()))
		}
		var pluginPage []Catalog
		var err error
		pluginPage, plgs, err = s.pluginRepo.ListCatalogs(ctx, projectIds, opts...)
		if err != nil {
			return nil, err
		}
		staticPage, err := s.staticRepo.ListCatalogs(ctx, projectIds, opts...)
		if err != nil {
			return nil, err
		}
		page := append(pluginPage, staticPage...)
		slices.SortFunc(page, func(i, j Catalog) int {
			return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
		})
		// Truncate slice to at most limit number of elements
		if len(page) > limit {
			page = page[:limit]
		}
		return page, nil
	}
	// Wrap the filter function in a callback that captures the plugins returned from
	// the list operation, so the plugins can be used when filtering.
	paginationFilterItemFn := func(ctx context.Context, item Catalog) (bool, error) {
		return filterItemFn(ctx, item, plgs)
	}
	estimatedCountFn := func(ctx context.Context) (int, error) {
		pluginCount, err := s.pluginRepo.EstimatedCatalogCount(ctx)
		if err != nil {
			return 0, err
		}
		staticCount, err := s.staticRepo.EstimatedCatalogCount(ctx)
		if err != nil {
			return 0, err
		}
		return pluginCount + staticCount, nil
	}
	listDeletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Request and combine deleted ids from the DB for generic and ssh cert catalogs.
		// This statement here is the reason we need a struct for this. We need all the
		// deleted auth methods to be collated in a single transaction with a single
		// transaction timestamp. This requires access to a db Reader, which isn't available
		// to the handlers and can't be passed into this method. Therefore, a struct,
		// constructed in the controller, is necessary.
		var deletedIds []string
		var transactionTimestamp time.Time
		if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
			pluginIds, err := s.pluginRepo.ListDeletedCatalogIds(ctx, since, WithReaderWriter(r, w))
			if err != nil {
				return err
			}
			staticIds, err := s.staticRepo.ListDeletedCatalogIds(ctx, since, WithReaderWriter(r, w))
			if err != nil {
				return err
			}
			deletedIds = append(pluginIds, staticIds...)
			transactionTimestamp, err = r.Now(ctx)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return nil, time.Time{}, err
		}
		return deletedIds, transactionTimestamp, nil
	}

	resp, err := pagination.ListRefresh(ctx, grantsHash, pageSize, paginationFilterItemFn, listItemsFn, estimatedCountFn, listDeletedIDsFn, tok)
	if err != nil {
		return nil, nil, err
	}
	return resp, plgs, nil
}
