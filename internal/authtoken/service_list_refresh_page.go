// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListRefreshPage lists up to page size auth tokens, filtering out entries that
// do not pass the filter item function. It will automatically request
// more auth tokens from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Auth tokens are ordered by update time descending (most recently updated first).
// Auth tokens may contain items that were already returned during the initial
// pagination phase. It also returns a list of any auth tokens deleted since the
// last response.
func ListRefreshPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*AuthToken],
	tok *listtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*AuthToken], error) {
	const op = "authtoken.ListRefreshPage"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case withScopeIds == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}
	rt, ok := tok.Subtype.(*listtoken.RefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *AuthToken, limit int) ([]*AuthToken, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		} else {
			lastItem, err := tok.LastItem(ctx)
			if err != nil {
				return nil, time.Time{}, err
			}
			opts = append(opts, WithStartPageAfterItem(lastItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the original list pagination phase.
		return repo.listAuthTokensRefresh(ctx, rt.PhaseLowerBound.Add(-globals.RefreshReadLookbackDuration), withScopeIds, opts...)
	}

	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletes missed due to concurrent
		// transactions in the original list pagination phase.
		return repo.listDeletedIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount, listDeletedIdsFn, tok)
}
