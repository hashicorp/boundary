// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
)

// ListFilterCatalogFunc is used to filter out catalogs after retrieval from the DB.
type ListFilterCatalogFunc func(context.Context, Catalog, []*plugin.Plugin) (bool, error)

// List lists host catalogs according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned catalogs.
func (s *CatalogService) List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterCatalogFunc,
	projectIds []string,
) (*pagination.ListResponse[Catalog], []*plugin.Plugin, error) {
	const op = "host.(*CatalogService).List"

	if len(grantsHash) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if len(projectIds) == 0 {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	}

	var plgs []*plugin.Plugin
	listItemsFn := func(ctx context.Context, lastPageItem Catalog, limit int) ([]Catalog, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Request another page from the DB until we fill the final items
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
	// Wrap the filter function in a callback that captures the plugins returned from
	// the list operation, so the plugins can be used when filtering.
	paginationFilterItemFn := func(ctx context.Context, item Catalog) (bool, error) {
		return filterItemFn(ctx, item, plgs)
	}

	resp, err := pagination.List(ctx, grantsHash, pageSize, paginationFilterItemFn, listItemsFn, estimatedCountFn)
	if err != nil {
		return nil, nil, err
	}
	return resp, plgs, nil
}
