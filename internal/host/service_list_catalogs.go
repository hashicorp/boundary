// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	ppagination "github.com/hashicorp/boundary/internal/pagination/plugin"
	"github.com/hashicorp/boundary/internal/plugin"
)

// ListCatalogs lists up to page size host catalogs, filtering out entries that
// do not pass the filter item function. It also returns a map from plugin ID to
// plugin associated with the returned catalogs. The map may contain a superset of
// the plugins associated with the catalogs. It will automatically request
// more host catalogs from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Host catalogs are ordered by create time descending (most recently created first).
func ListCatalogs(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ppagination.ListPluginsFilterFunc[Catalog],
	repo *CatalogRepository,
	projectIds []string,
) (*pagination.ListResponse[Catalog], map[string]*plugin.Plugin, error) {
	const op = "host.ListCatalogs"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case projectIds == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case repo == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case len(projectIds) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Catalog, limit int) ([]Catalog, []*plugin.Plugin, time.Time, error) {
		return repo.List(ctx, projectIds, lastPageItem, limit)
	}

	return ppagination.ListPlugins(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount)
}
