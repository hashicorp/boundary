// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"

	"github.com/hashicorp/boundary/internal/pagination"
)

// This function is a callback passed down from the application service layer
// used to filter out protobuf stores that don't match any user-supplied filter.
type ListFilterStoreFunc func(Store) (bool, error)

// List lists credential stores according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned stores.
func (s *StoreService) List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Store],
	projectIds []string,
) (*pagination.ListResponse2[Store], error) {
	listItemsFn := func(ctx context.Context, lastPageItem Store, limit int) ([]Store, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		}
		// Request another page from the DB until we fill the final items
		var page []Store
		for _, repo := range s.repos {
			repoPage, err := repo.ListCredentialStores(ctx, projectIds, opts...)
			if err != nil {
				return nil, err
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
		return page, nil
	}
	estimatedCountFn := func(ctx context.Context) (int, error) {
		var totalItems int
		for _, repo := range s.repos {
			numItems, err := repo.EstimatedStoreCount(ctx)
			if err != nil {
				return 0, nil
			}
			totalItems += numItems
		}
		return totalItems, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn)
}
