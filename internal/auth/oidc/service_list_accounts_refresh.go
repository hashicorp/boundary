// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListAccountsRefresh lists accounts according to the page size
// and refresh token, filtering out entries that do not
// pass the filter item fn. It returns a new refresh token
// based on the old one, the grants hash, and the returned
// accounts.
func ListAccountsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.Account],
	tok *refreshtoken.Token,
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.Account], error) {
	const op = "oidc.ListAccountsRefresh"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if tok == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	}
	if repo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	}
	if authMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}

	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem auth.Account, limit int) ([]auth.Account, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		} else {
			opts = append(opts,
				WithStartPageAfterItem(tok.LastItem()),
			)
		}
		accts, err := repo.ListAccounts(ctx, authMethodId, opts...)
		if err != nil {
			return nil, err
		}
		var items []auth.Account
		for _, i := range accts {
			items = append(items, i)
		}
		return items, nil
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedAccountCount, repo.listDeletedAccountIds, tok)
}
