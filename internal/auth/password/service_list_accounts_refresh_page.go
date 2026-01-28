// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListAccountsRefreshPage lists up to page size accounts, filtering out entries that
// do not pass the filter item function. It will automatically request
// more accounts from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Accounts are ordered by update time descending (most recently updated first).
// Accounts may contain items that were already returned during the initial
// pagination phase. It also returns a list of any accounts deleted since the
// last response.
func ListAccountsRefreshPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.Account],
	tok *listtoken.Token,
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.Account], error) {
	const op = "password.ListAccountsRefreshPage"

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
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method ID")
	case tok.ResourceType != resource.Account:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have an account resource type")
	}
	rt, ok := tok.Subtype.(*listtoken.RefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem auth.Account, limit int) ([]auth.Account, time.Time, error) {
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
		sAccounts, listTime, err := repo.listAccountsRefresh(ctx, authMethodId, rt.PhaseLowerBound.Add(-globals.RefreshReadLookbackDuration), opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var accounts []auth.Account
		for _, account := range sAccounts {
			accounts = append(accounts, account)
		}
		return accounts, listTime, nil
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletes missed due to concurrent
		// transactions in the original list pagination phase.
		return repo.listDeletedAccountIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedAccountCount, listDeletedIdsFn, tok)
}
