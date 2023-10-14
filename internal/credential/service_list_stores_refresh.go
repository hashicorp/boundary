// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"slices"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credential stores according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned stores.
func (s *StoreService) ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Store],
	tok *refreshtoken.Token,
	projectIds []string,
) (*pagination.ListResponse2[Store], error) {
	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem Store, limit int) ([]Store, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		} else {
			opts = append(opts,
				WithStartPageAfterItem(tok.ToPartialResource()),
			)
		}
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
				return 0, err
			}
			totalItems += numItems
		}
		return totalItems, nil
	}

	listDeletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
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
					return err
				}
				deletedIds = append(deletedIds, deletedRepoIds...)
			}
			var err error
			transactionTimestamp, err = r.Now(ctx)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return nil, time.Time{}, err
		}
		return deletedIds, transactionTimestamp, nil
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, estimatedCountFn, listDeletedIDsFn, tok)
}
