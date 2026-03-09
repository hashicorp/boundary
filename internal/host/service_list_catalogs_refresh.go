// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package host

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	ppagination "github.com/hashicorp/boundary/internal/pagination/plugin"
	"github.com/hashicorp/boundary/internal/plugin"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListCatalogsRefresh lists up to page size host catalogs, filtering out entries that
// do not pass the filter item function. It also returns a map from plugin ID to
// plugin associated with the returned catalogs. The map may contain a superset of
// the plugins associated with the catalogs. It will automatically request
// more host catalogs from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Host catalogs are ordered by update time descending (most recently updated first).
// Host catalogs may contain items that were already returned during the initial
// pagination phase. It also returns a list of any host catalogs deleted since the
// start of the initial pagination phase or last response.
func ListCatalogsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ppagination.ListPluginsFilterFunc[Catalog],
	tok *listtoken.Token,
	repo *CatalogRepository,
	projectIds []string,
) (*pagination.ListResponse[Catalog], map[string]*plugin.Plugin, error) {
	const op = "host.ListCatalogsRefresh"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case projectIds == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case repo == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case len(projectIds) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case tok.ResourceType != resource.HostCatalog:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a host catalog resource type")
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Catalog, limit int) ([]Catalog, []*plugin.Plugin, time.Time, error) {
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.ListRefresh(ctx, projectIds, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), lastPageItem, limit)
	}
	listDeletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		since = since.Add(-globals.RefreshReadLookbackDuration)
		return repo.ListDeletedIds(ctx, since)
	}

	return ppagination.ListPluginsRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount, listDeletedIDsFn, tok)
}
