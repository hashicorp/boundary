// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListAccountsPage lists up to page size password accounts, filtering out entries that
// do not pass the filter item function. It will automatically request
// more password accounts from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Accounts are ordered by create time descending (most recently created first).
func ListAccountsPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.Account],
	tok *listtoken.Token,
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.Account], error) {
	const op = "password.ListAccountsPage"

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
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
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
		passwordAccounts, listTime, err := repo.listAccounts(ctx, authMethodId, opts...)
		if err != nil {
			return nil, time.Time{}, err
		}
		var accts []auth.Account
		for _, acct := range passwordAccounts {
			accts = append(accts, acct)
		}
		return accts, listTime, nil
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedAccountCount, tok)
}
