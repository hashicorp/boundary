// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
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
	// RefreshToken is the token that the caller can use
	// to request a new page of items. The items in the
	// new page will have been updated more recently
	// than all the items in the previous page. This
	// field may be empty if there were no results for a
	// List call.
	RefreshToken *refreshtoken.Token
	// DeletedIds contains a list of item IDs that have been
	// deleted since the last request for items. This can happen
	// both during the initial pagination or when requesting a
	// refresh. This is always empty for the initial List call.
	DeletedIds []string
	// EstimatedItemCount is an estimate on exactly how many
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

// ListItemsFunc returns a slice of T that have been updated since prevPageLastItem.
// If prevPageLastItem is empty, it returns a slice of T starting with the least recently updated.
type ListItemsFunc[T boundary.Resource] func(ctx context.Context, prevPageLastItem T, limit int) ([]T, error)

// ListRefreshItemsFunc returns a slice of T that have been updated since prevPageLastItem.
// If prevPageLastItem is empty, it returns a slice of T that have been updated since the
// item in the refresh token.
type ListRefreshItemsFunc[T boundary.Resource] func(ctx context.Context, tok *refreshtoken.Token, prevPageLastItem T, limit int) ([]T, error)

// EstimatedCountFunc is used to estimate the total number of items
// available for the resource that is being listed.
type EstimatedCountFunc func(ctx context.Context) (int, error)

// ListDeletedIDsFunc is used to list the IDs of the resources deleted since
// the given timestamp. It returns a slice of IDs and the timestamp of the
// instant in which the slice was created.
type ListDeletedIDsFunc func(ctx context.Context, since time.Time) ([]string, time.Time, error)

// List returns a ListResponse. The response will contain at most a
// number of items equal to the pageSize. Items are fetched using the
// listItemsFn and then items are checked using the filterItemFn
// to determine if they should be included in the response.
// The response includes a new refresh token based on the grants and items.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the provided
// refresh token.
func List[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
	estimatedCountFn EstimatedCountFunc,
) (*ListResponse[T], error) {
	const op = "pagination.List"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if listItemsFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list items callback")
	}
	if estimatedCountFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	}

	items, completeListing, err := list(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := &ListResponse[T]{
		Items:              items,
		CompleteListing:    completeListing,
		EstimatedItemCount: len(items),
	}

	if !completeListing {
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
		var err error
		resp.EstimatedItemCount, err = estimatedCountFn(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	if len(items) > 0 {
		resp.RefreshToken = refreshtoken.FromResource(items[len(items)-1], grantsHash)
	}

	return resp, nil
}

// ListRefresh returns a ListResponse. The response will contain at most a
// number of items equal to the pageSize. Items are fetched using the
// listRefreshItemsFn and then items are checked using the filterItemFn
// to determine if they should be included in the response.
// The response includes a new refresh token based on the grants and items.
// The estimatedCountFn is used to provide an estimated total number of
// items that can be returned by making additional requests using the provided
// refresh token. The listDeletedIDsFn is used to list the IDs of any
// resources that have been deleted since the refresh token was last used.
func ListRefresh[T boundary.Resource](
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listRefreshItemsFn ListRefreshItemsFunc[T],
	estimatedCountFn EstimatedCountFunc,
	listDeletedIDsFn ListDeletedIDsFunc,
	tok *refreshtoken.Token,
) (*ListResponse[T], error) {
	const op = "pagination.ListRefresh"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if listRefreshItemsFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list refresh items callback")
	}
	if estimatedCountFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing estimated count callback")
	}
	if listDeletedIDsFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing list deleted IDs callback")
	}
	if tok == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing refresh token")
	}

	deletedIds, transactionTimestamp, err := listDeletedIDsFn(ctx, tok.UpdatedTime)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	listItemsFn := func(ctx context.Context, prevPageLast T, limit int) ([]T, error) {
		return listRefreshItemsFn(ctx, tok, prevPageLast, limit)
	}

	items, completeListing, err := list(ctx, pageSize, filterItemFn, listItemsFn)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := &ListResponse[T]{
		Items:           items,
		CompleteListing: completeListing,
		DeletedIds:      deletedIds,
	}

	resp.EstimatedItemCount, err = estimatedCountFn(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	if len(items) > 0 {
		resp.RefreshToken = tok.RefreshLastItem(items[len(items)-1], transactionTimestamp)
	} else {
		resp.RefreshToken = tok.Refresh(transactionTimestamp)
	}

	return resp, nil
}

func list[T boundary.Resource](
	ctx context.Context,
	pageSize int,
	filterItemFn ListFilterFunc[T],
	listItemsFn ListItemsFunc[T],
) ([]T, bool, error) {
	const op = "pagination.list"

	var lastItem T
	limit := pageSize + 1
	items := make([]T, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, err := listItemsFn(ctx, lastItem, limit)
		if err != nil {
			return nil, false, errors.Wrap(ctx, err, op)
		}
		for _, item := range page {
			ok, err := filterItemFn(ctx, item)
			if err != nil {
				return nil, false, errors.Wrap(ctx, err, op)
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

	return items, completeListing, nil
}
