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

// ListPluginFilterFunc is a callback used to filter out resources that don't match
// some criteria. The function must return true for items that should be included in the final
// result. Returning an error results in an error being returned from the pagination.
type ListPluginFilterFunc[T boundary.Resource] func(ctx context.Context, item T, plugin *plugin.Plugin) (bool, error)

// ListPluginItemsFunc returns a slice of T that are ordered after prevPageLastItem according to
// the implementation of the function. If prevPageLastItem is empty, it should return
// a slice of T from the start, as defined by the function. It also returns the timestamp
// of the DB transaction used to list the items.
type ListPluginItemsFunc[T boundary.Resource] func(ctx context.Context, prevPageLastItem T, limit int) ([]T, *plugin.Plugin, time.Time, error)

// ListPlugin returns a ListResponse and a plugin associated with the resources.
// The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token.
func ListPlugin[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginFilterFunc[T],
	listItemsFn ListPluginItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
) (*pagination.ListResponse[T], *plugin.Plugin, error) {
	const op = "pagination.ListPlugin"

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

	items, plg, completeListing, listTime, err := listPlugin(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListResp(ctx, grantsHash, items, completeListing, listTime, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plg, nil
}

// ListPluginPage returns a ListResponse and a plugin associated with the resources.
// The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a PaginationToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token.
func ListPluginPage[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginFilterFunc[T],
	listItemsFn ListPluginItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
	tok *listtoken.Token,
) (*pagination.ListResponse[T], *plugin.Plugin, error) {
	const op = "pagination.ListPluginPage"

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

	items, plg, completeListing, listTime, err := listPlugin(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListPageResp(ctx, completeListing, nil, time.Time{} /* no deleted ids time */, items, listTime, tok, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plg, nil
}

// ListPluginRefresh returns a ListResponse and a plugin associated with the resources.
// The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a StartRefreshToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the list token was last used.
func ListPluginRefresh[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginFilterFunc[T],
	listItemsFn ListPluginItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
	listDeletedIDsFn pagination.ListDeletedIDsFunc,
	tok *listtoken.Token,
) (*pagination.ListResponse[T], *plugin.Plugin, error) {
	const op = "pagination.ListPluginRefresh"

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

	items, plg, completeListing, listTime, err := listPlugin(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListPageResp(ctx, completeListing, deletedIds, deletedIdsTime, items, listTime, tok, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plg, nil
}

// ListPluginRefreshPage returns a ListResponse and a plugin associated with the resources.
// The response will contain at most pageSize number of items.
// Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a RefreshToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the list token was last used.
func ListPluginRefreshPage[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListPluginFilterFunc[T],
	listItemsFn ListPluginItemsFunc[T],
	estimatedCountFn pagination.EstimatedCountFunc,
	listDeletedIDsFn pagination.ListDeletedIDsFunc,
	tok *listtoken.Token,
) (*pagination.ListResponse[T], *plugin.Plugin, error) {
	const op = "pagination.ListPluginRefreshPage"

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

	items, plg, completeListing, listTime, err := listPlugin(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	resp, err := buildListPageResp(ctx, completeListing, deletedIds, deletedIdsTime, items, listTime, tok, estimatedCountFn)
	if err != nil {
		return nil, nil, errors.Wrap(ctx, err, op)
	}

	return resp, plg, nil
}

func listPlugin[T boundary.Resource](
	ctx context.Context,
	pageSize int,
	filterItemFn ListPluginFilterFunc[T],
	listItemsFn ListPluginItemsFunc[T],
) ([]T, *plugin.Plugin, bool, time.Time, error) {
	const op = "pagination.list"

	var lastItem T
	var plg *plugin.Plugin
	var firstListTime time.Time
	limit := pageSize + 1
	items := make([]T, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, newPlg, listTime, err := listItemsFn(ctx, lastItem, limit)
		if err != nil {
			return nil, nil, false, time.Time{}, errors.Wrap(ctx, err, op)
		}
		// Assign the firstListTime once, to ensure we always store the start of listing,
		// rather the timestamp of the last listing.
		if firstListTime.IsZero() {
			firstListTime = listTime
		}
		if plg == nil {
			plg = newPlg
		} else if newPlg != nil && plg.PublicId != newPlg.PublicId {
			return nil, nil, false, time.Time{}, errors.New(ctx, errors.Internal, op, "plugin changed between list invocations")
		}
		for _, item := range page {
			ok, err := filterItemFn(ctx, item, plg)
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

	return items, plg, completeListing, firstListTime, nil
}

func buildListResp[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	items []T,
	completeListing bool,
	listTime time.Time,
	estimatedCountFn pagination.EstimatedCountFunc,
) (*pagination.ListResponse[T], error) {
	resp := &pagination.ListResponse[T]{
		Items:              items,
		CompleteListing:    completeListing,
		EstimatedItemCount: len(items),
	}

	var err error
	if len(items) > 0 {
		lastItem := items[len(items)-1]

		if completeListing {
			// If this is the only page in the pagination, create a
			// start refresh token so subsequent requests are informed
			// that they need to start a new refresh phase.
			resp.ListToken, err = listtoken.NewStartRefresh(
				ctx,
				listTime, // Use list time as the create time of the token
				lastItem.GetResourceType(),
				grantsHash,
				listTime, // Use list time as the starting point for listing deleted ids
				listTime, // Use list time as the lower bound for subsequent refresh
			)
			if err != nil {
				return nil, err
			}
		} else {
			resp.ListToken, err = listtoken.NewPagination(
				ctx,
				listTime, // Use list time as the create time of the token
				lastItem.GetResourceType(),
				grantsHash,
				lastItem.GetPublicId(),
				lastItem.GetCreateTime().AsTime(),
			)
			if err != nil {
				return nil, err
			}
		}
	}
	if !completeListing {
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
		var err error
		resp.EstimatedItemCount, err = estimatedCountFn(ctx)
		if err != nil {
			return nil, err
		}
	}
	return resp, err
}

func buildListPageResp[T boundary.Resource](
	ctx context.Context,
	completeListing bool,
	deletedIds []string,
	deletedIdsTime time.Time,
	items []T,
	listTime time.Time,
	tok *listtoken.Token,
	estimatedCountFn pagination.EstimatedCountFunc,
) (*pagination.ListResponse[T], error) {
	resp := &pagination.ListResponse[T]{
		Items:           items,
		CompleteListing: completeListing,
		ListToken:       tok,
		DeletedIds:      deletedIds,
	}

	var err error
	resp.EstimatedItemCount, err = estimatedCountFn(ctx)
	if err != nil {
		return nil, err
	}
	var lastItem boundary.Resource
	if len(items) > 0 {
		lastItem = items[len(items)-1]
	}
	if err := resp.ListToken.Transition(
		ctx,
		completeListing,
		lastItem,
		deletedIdsTime,
		listTime,
	); err != nil {
		return nil, err
	}
	return resp, err
}
