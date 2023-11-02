// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListRoles lists roles according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned roles.
func ListRoles(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Role],
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*Role], error) {
	const op = "iam.ListRoles"

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

	listItemsFn := func(ctx context.Context, lastPageItem *Role, limit int) ([]*Role, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		}
		roles, err := repo.ListRoles(ctx, withScopeIds, opts...)
		if err != nil {
			return nil, err
		}
		return roles, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedRolesCount)
}
