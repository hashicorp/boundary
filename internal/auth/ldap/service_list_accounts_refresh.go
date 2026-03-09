// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

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

// ListAccountsRefresh lists ldap accounts according to the page size
// and list token, filtering out entries that do not
// pass the filter item fn. It returns a new list token
// based on the old one, the grants hash, and the returned
// ldap accounts.
func ListAccountsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.Account],
	tok *listtoken.Token,
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.Account], error) {
	const op = "ldap.ListAccountsRefresh"

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
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem auth.Account, limit int) ([]auth.Account, time.Time, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(ctx, lastPageItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		ldapAccounts, listTime, err := repo.listAccountsRefresh(ctx, authMethodId, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var accounts []auth.Account
		for _, account := range ldapAccounts {
			accounts = append(accounts, account)
		}
		return accounts, listTime, nil
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletes missed due to concurrent
		// transactions in the original list pagination phase.
		return repo.listDeletedAccountIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedAccountCount, listDeletedIdsFn, tok)
}
