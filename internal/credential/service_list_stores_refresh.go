// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credential stores according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned stores.
func (s *StoreService) ListRefresh(
	ctx context.Context,
	projectIds []string,
	tok *refreshtoken.Token,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterStoreFunc,
) (*ListStoresResponse, error) {
	const op = "credential.ListRefresh"

	// Request and combine deleted ids from the DB for generic and ssh cert stores.
	// This statement here is the reason we need a struct for this. We need all the
	// deleted auth methods to be collated in a single transaction with a single
	// transaction timestamp. This requires access to a db Reader, which isn't available
	// to the handlers and can't be passed into this method. Therefore, a struct,
	// constructed in the controller, is necessary.
	var deletedIds []string
	var transactionTimestamp time.Time
	if _, err := s.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{}, func(r db.Reader, w db.Writer) error {
		for _, repo := range s.repos {
			deletedRepoIds, err := repo.ListDeletedStoreIds(ctx, tok.UpdatedTime, WithReaderWriter(r, w))
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			deletedIds = append(deletedIds, deletedRepoIds...)
		}
		var err error
		transactionTimestamp, err = r.Now(ctx)
		if err != nil {
			return errors.Wrap(ctx, err, op)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
		WithStartPageAfterItem(tok.LastItemId, tok.LastItemUpdatedTime),
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
			WithStartPageAfterItem(page[len(page)-1].GetPublicId(), page[len(page)-1].GetUpdateTime().AsTime()),
		}
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(stores) < cap(stores)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		stores = stores[:pageSize]
		// If this was not a complete listing, get an estimate
		// of the total items from the DB.
	}

	var totalItems int
	for _, repo := range s.repos {
		numItems, err := repo.EstimatedStoreCount(ctx)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		totalItems += numItems
	}

	resp := &ListStoresResponse{
		Items:               stores,
		DeletedIds:          deletedIds,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	// Use the timestamp of the deleted IDs transaction with a
	// buffer to account for overlapping transactions. It is okay
	// to return a deleted ID more than once. The buffer corresponds
	// to Postgres' default transaction timeout.
	updatedTime := transactionTimestamp.Add(-30 * time.Second)
	if updatedTime.Before(tok.CreatedTime) {
		// Ensure updated time isn't before created time due
		// to the buffer.
		updatedTime = tok.CreatedTime
	}
	if len(stores) > 0 {
		resp.RefreshToken = tok.RefreshLastItem(stores[len(stores)-1], updatedTime)
	} else {
		resp.RefreshToken = tok.Refresh(updatedTime)
	}

	return resp, nil
}
