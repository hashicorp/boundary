// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// This function is a callback passed down from the application service layer
// used to filter out protobuf stores that don't match any user-supplied filter.
type ListFilterStoreFunc func(Store) (bool, error)

// List lists credential stores according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned stores.
func (s *StoreService) List(
	ctx context.Context,
	projectIds []string,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterStoreFunc,
) (*ListStoresResponse, error) {
	const op = "credential.List"

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
	}

	stores := make([]Store, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		var page []Store
		for _, repo := range s.repos {
			repoPage, err := repo.ListCredentialStores(ctx, projectIds, opts...)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			page = append(page, repoPage...)
		}
		slices.SortFunc(page, func(i, j Store) int {
			return i.GetUpdateTime().AsTime().Compare(j.GetUpdateTime().AsTime())
		})
		// Truncate slice to at most limit number of elements
		if len(page) > limit {
			page = page[:limit]
		}
		for _, item := range page {
			ok, err := filterItemFn(item)
			if err != nil {
				return nil, err
			}
			if ok {
				stores = append(stores, item)
				// If we filled the items after filtering,
				// we're done.
				if len(stores) == cap(stores) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		opts = []Option{
			WithLimit(limit),
			WithStartPageAfterItem(page[len(page)-1]),
		}
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(stores) < cap(stores)
	totalItems := len(stores)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		stores = stores[:pageSize]
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
		totalItems = 0
		for _, repo := range s.repos {
			numItems, err := repo.EstimatedStoreCount(ctx)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			totalItems += numItems
		}
	}

	resp := &ListStoresResponse{
		Items:               stores,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	if len(stores) > 0 {
		resp.RefreshToken = refreshtoken.FromResource(stores[len(stores)-1], grantsHash)
	}

	return resp, nil
}
