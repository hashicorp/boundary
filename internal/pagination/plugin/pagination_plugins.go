// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/plugin"
)

// ListPluginsFilterFunc is a callback used to filter out resources that don't match
// some criteria. The function must return true for items that should be included in the final
// result. Returning an error results in an error being returned from the pagination.
type ListPluginsFilterFunc[T boundary.Resource] func(ctx context.Context, item T, plugin map[string]*plugin.Plugin) (bool, error)

// ListPluginsItemsFunc returns a slice of T that are ordered after prevPageLastItem according to
// the implementation of the function. If prevPageLastItem is empty, it should return
// a slice of T from the start, as defined by the function. It also returns the timestamp
// of the DB transaction used to list the items.
type ListPluginsItemsFunc[T boundary.Resource] func(ctx context.Context, prevPageLastItem T, limit int) ([]T, []*plugin.Plugin, time.Time, error)

// ListPlugins returns a ListResponse and a map of plugin id to the plugins associated
// with the returned resources. The map may contain a superset of the plugins associated with
// the plugins. The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token.
func ListPlugins[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginsFilterFunc[T],
	listItemsFn ListPluginsItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
) (*pagination.ListResponse[T], map[string]*plugin.Plugin, error) {
	const op = "pagination.ListsPlugin"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	}

	items, plgs, completeListing, listTime, err := listPlugins(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListResp(ctx, grantsHash, items, completeListing, listTime, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plgs, nil
}

// ListPluginsPage returns a ListResponse and a map of plugin id to the plugins associated
// with the returned resources. The map may contain a superset of the plugins associated with
// the plugins. The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a PaginationToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token.
func ListPluginsPage[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginsFilterFunc[T],
	listItemsFn ListPluginsItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
	tok *listtoken.Token,
) (*pagination.ListResponse[T], map[string]*plugin.Plugin, error) {
	const op = "pagination.ListPluginsPage"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	case tok == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list token")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	items, plgs, completeListing, listTime, err := listPlugins(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListPageResp(ctx, completeListing, nil, time.Time{} /* no deleted ids time */, items, listTime, tok, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plgs, nil
}

// ListPluginsRefresh returns a ListResponse and a map of plugin id to the plugins associated
// with the returned resources. The map may contain a superset of the plugins associated with
// the plugins. The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a StartRefreshToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the list token was last used.
func ListPluginsRefresh[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginsFilterFunc[T],
	listItemsFn ListPluginsItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
	listDeletedIDsFn pagination.ListDeletedIDsFunc,
	tok *listtoken.Token,
) (*pagination.ListResponse[T], map[string]*plugin.Plugin, error) {
	const op = "pagination.ListPluginsRefresh"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	case listDeletedIDsFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list deleted IDs callback")
	case tok == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list token")
	}
	srt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	deletedIds, deletedIdsTime, err := listDeletedIDsFn(ctx, srt.PreviousDeletedIdsTime)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	items, plgs, completeListing, listTime, err := listPlugins(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListPageResp(ctx, completeListing, deletedIds, deletedIdsTime, items, listTime, tok, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plgs, nil
}

// ListPluginsRefreshPage returns a ListResponse and a map of plugin id to the plugins associated
// with the returned resources. The map may contain a superset of the plugins associated with
// the plugins. The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a RefreshToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the list token was last used.
func ListPluginsRefreshPage[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginsFilterFunc[T],
	listItemsFn ListPluginsItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
	listDeletedIDsFn pagination.ListDeletedIDsFunc,
	tok *listtoken.Token,
) (*pagination.ListResponse[T], map[string]*plugin.Plugin, error) {
	const op = "pagination.ListPluginsRefreshPage"

	switch {
	case len(grantsHash) == 0:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	case listDeletedIDsFn == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list deleted IDs callback")
	case tok == nil:
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "missing list token")
	}
	rt, ok := tok.Subtype.(*listtoken.RefreshToken)
	if !ok {
		return nil, nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a refresh token component")
	}

	deletedIds, deletedIdsTime, err := listDeletedIDsFn(ctx, rt.PreviousDeletedIdsTime)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	items, plgs, completeListing, listTime, err := listPlugins(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListPageResp(ctx, completeListing, deletedIds, deletedIdsTime, items, listTime, tok, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plgs, nil
}

func listPlugins[T boundary.Resource](
	ctx context.Context,
	pageSize int,
	filterItemFn ListPluginsFilterFunc[T],
	listItemsFn ListPluginsItemsFunc[T],
) ([]T, map[string]*plugin.Plugin, bool, time.Time, error) {
	const op = "pagination.list"

	var lastItem T
	plgs := map[string]*plugin.Plugin{}
	var firstListTime time.Time
	limit := pageSize + 1
	items := make([]T, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, newPlgs, listTime, err := listItemsFn(ctx, lastItem, limit)
		if err != nil {
			return nil, nil, false, time.Time{}, errors.Wrap(ctx, err, op)
		}
		// Assign the firstListTime once, to ensure we always store the start of listing,
		// rather the timestamp of the last listing.
		if firstListTime.IsZero() {
			firstListTime = listTime
		}
		for _, plg := range newPlgs {
			if _, ok := plgs[plg.PublicId]; !ok {
				plgs[plg.PublicId] = plg
			}
		}
		for _, item := range page {
			ok, err := filterItemFn(ctx, item, plgs)
			if err != nil {
				return nil, nil, false, time.Time{}, errors.Wrap(ctx, err, op)
			}
			if ok {
				items = append(items, item)
				// If we filled the items after filtering,
				// we're done.
				if len(items) == cap(items) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		lastItem = page[len(page)-1]
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(items) < cap(items)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		items = items[:pageSize]
	}

	// Note that plgs can contain a superset of the plugins associated with the items,
	// since we get plugins from the listFn based on a limit of pageSize+1. If the last
	// item that we request is removed, there is no way to tell if a plugin was associated
	// with that item only. This is fine in practice, as callers should never loop over
	// the map, they should look up plugins by ID from the resource used.
	return items, plgs, completeListing, firstListTime, nil
}
