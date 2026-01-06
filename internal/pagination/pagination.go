// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
)

// ListResponse represents the response from the paginated list operation.
type ListResponse[T boundary.Resource] struct {
	// Items contains the page of items. They have
	// been filtered according to the behavior of
	// the filter item func, and will always have as
	// many items as requested in the page size, unless
	// there were not enough elements available, in
	// which case it will contain all elements that
	// were available.
	Items []T
	// CompleteListing signifies whether this page contains
	// the final item currently available. This indicates
	// that it may be appropriate to wait some time before
	// requesting additional pages.
	CompleteListing bool
	// ListToken is the token that the caller can use
	// to request a new page of items. The items in the
	// new page will have been updated more recently
	// than all the items in the previous page. This
	// field may be empty if there were no results for a
	// List call.
	ListToken *listtoken.Token
	// DeletedIds contains a list of item IDs that have been
	// deleted since the last request for items. This can only happen
	// during a refresh pagination.
	DeletedIds []string
	// EstimatedItemCount is an estimate of exactly how many
	// items matching the filter function are available. If
	// a List call is complete, this number is equal to
	// the number of items returned. Otherwise, the
	// estimated count function is consulted for an estimate.
	EstimatedItemCount int
}

// ListFilterFunc is a callback used to filter out resources that don't match
// some criteria. The function must return true for items that should be included in the final
// result. Returning an error results in an error being returned from the pagination.
type ListFilterFunc[T boundary.Resource] func(ctx context.Context, item T) (bool, error)

// ListItemsFunc returns a slice of T that are ordered after prevPageLastItem according to
// the implementation of the function. If prevPageLastItem is empty, it should return
// a slice of T from the start, as defined by the function. It also returns the timestamp
// of the DB transaction used to list the items.
type ListItemsFunc[T boundary.Resource] func(ctx context.Context, prevPageLastItem T, limit int) ([]T, time.Time, error)

// EstimatedCountFunc is used to estimate the total number of items
// available for the resource that is being listed.
type EstimatedCountFunc func(ctx context.Context) (int, error)

// ListDeletedIDsFunc is used to list the IDs of the resources deleted since
// the given timestamp. It returns a slice of IDs and the timestamp of the
// DB transaction used to list the IDs.
type ListDeletedIDsFunc func(ctx context.Context, since time.Time) ([]string, time.Time, error)

// List returns a ListResponse. The response will contain at most pageSize
// number of items. Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token.
func List[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
	estimatedCountFn EstimatedCountFunc,
) (*ListResponse[T], error) {
	const op = "pagination.List"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	}

	items, completeListing, listTime, err := list(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return buildListResp(ctx, grantsHash, items, completeListing, listTime, estimatedCountFn)
}

// ListPage returns a ListResponse. The response will contain at most pageSize
// number of items. Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a PaginationToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token.
func ListPage[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
	estimatedCountFn EstimatedCountFunc,
	tok *listtoken.Token,
) (*ListResponse[T], error) {
	const op = "pagination.ListPage"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list token")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	items, completeListing, listTime, err := list(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return buildListPageResp(ctx, completeListing, nil, time.Time{} /* no deleted ids time */, items, listTime, tok, estimatedCountFn)
}

// ListRefresh returns a ListResponse. The response will contain at most pageSize
// number of items. Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a StartRefreshToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the list token was last used.
func ListRefresh[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
	estimatedCountFn EstimatedCountFunc,
	listDeletedIDsFn ListDeletedIDsFunc,
	tok *listtoken.Token,
) (*ListResponse[T], error) {
	const op = "pagination.ListRefresh"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	case listDeletedIDsFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list deleted IDs callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list token")
	}
	srt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	deletedIds, deletedIdsTime, err := listDeletedIDsFn(ctx, srt.PreviousDeletedIdsTime)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	items, completeListing, listTime, err := list(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return buildListPageResp(ctx, completeListing, deletedIds, deletedIdsTime, items, listTime, tok, estimatedCountFn)
}

// ListRefreshPage returns a ListResponse. The response will contain at most pageSize
// number of items. Items are fetched using the listItemsFn and checked using
// the filterItemFn to determine if they should be included in the response.
// Items will be fetched based on the contents of the list token. The list
// token must contain a RefreshToken component.
// The response includes a new list token used to continue pagination or refresh.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the returned
// list token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the list token was last used.
func ListRefreshPage[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
	estimatedCountFn EstimatedCountFunc,
	listDeletedIDsFn ListDeletedIDsFunc,
	tok *listtoken.Token,
) (*ListResponse[T], error) {
	const op = "pagination.ListRefreshPage"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case listItemsFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	case estimatedCountFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	case listDeletedIDsFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list deleted IDs callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list token")
	}
	rt, ok := tok.Subtype.(*listtoken.RefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a refresh token component")
	}

	deletedIds, deletedIdsTime, err := listDeletedIDsFn(ctx, rt.PreviousDeletedIdsTime)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	items, completeListing, listTime, err := list(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return buildListPageResp(ctx, completeListing, deletedIds, deletedIdsTime, items, listTime, tok, estimatedCountFn)
}

func list[T boundary.Resource](
	ctx context.Context,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
) ([]T, bool, time.Time, error) {
	const op = "pagination.list"

	var lastItem T
	var firstListTime time.Time
	limit := pageSize + 1
	items := make([]T, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, listTime, err := listItemsFn(ctx, lastItem, limit)
		if err != nil {
			return nil, false, time.Time{}, errors.Wrap(ctx, err, op)
		}
		// Assign the firstListTime once, to ensure we always store the start of listing,
		// rather the timestamp of the last listing.
		if firstListTime.IsZero() {
			firstListTime = listTime
		}
		for _, item := range page {
			ok, err := filterItemFn(ctx, item)
			if err != nil {
				return nil, false, time.Time{}, errors.Wrap(ctx, err, op)
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

	return items, completeListing, firstListTime, nil
}

func buildListResp[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	items []T,
	completeListing bool,
	listTime time.Time,
	estimatedCountFn EstimatedCountFunc,
) (*ListResponse[T], error) {
	resp := &ListResponse[T]{
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
	estimatedCountFn EstimatedCountFunc,
) (*ListResponse[T], error) {
	resp := &ListResponse[T]{
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
