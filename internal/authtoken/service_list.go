// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package authtoken

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// List lists auth tokens according to the page size,
// filtering out entries that do not
// pass the filter item fn. It returns a new refresh token
// based on the grants hash and the returned auth tokens.
func List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*AuthToken],
	repo *Repository,
	scopeIds []string,
) (*pagination.ListResponse[*AuthToken], error) {
	const op = "authtoken.List"

	if len(grantsHash) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	}
	if pageSize < 1 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	}
	if filterItemFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	}
	if repo == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	}
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope id(s)")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *AuthToken, limit int) ([]*AuthToken, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		}
		return repo.ListAuthTokens(ctx, scopeIds, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount)
}
