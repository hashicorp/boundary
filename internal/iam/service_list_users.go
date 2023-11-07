// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListUsers lists users according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned users.
func ListUsers(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*User],
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*User], error) {
	const op = "iam.ListUsers"

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
	if withScopeIds == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *User, limit int) ([]*User, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		}
		users, err := repo.ListUsers(ctx, withScopeIds, opts...)
		if err != nil {
			return nil, err
		}
		return users, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedUsersCount)
}
