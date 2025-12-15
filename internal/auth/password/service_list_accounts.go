// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListAccounts lists up to page size password accounts, filtering out entries that
// do not pass the filter item function. It will automatically request
// more accounts from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Accounts are ordered by create time descending (most recently created first).
func ListAccounts(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.Account],
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.Account], error) {
	const op = "password.ListAccounts"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case authMethodId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method ID")
	}

	listItemsFn := func(ctx context.Context, lastPageItem auth.Account, limit int) ([]auth.Account, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		passwordAccts, listTime, err := repo.listAccounts(ctx, authMethodId, opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var accounts []auth.Account
		for _, acct := range passwordAccts {
			accounts = append(accounts, acct)
		}
		return accounts, listTime, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedAccountCount)
}
