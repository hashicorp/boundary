// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRolesRefresh lists roles according to the page size
// and refresh token, filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the old one, the grants hash,
// and the returned roles.
func ListRolesRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Role],
	tok *refreshtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*Role], error) {
	const op = "iam.ListRolesRefresh"

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
	if withScopeIds == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	listItemsFn := func(ctx context.Context, tok *refreshtoken.Token, lastPageItem *Role, limit int) ([]*Role, error) {
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
		roles, err := repo.ListRoles(ctx, withScopeIds, opts...)
		if err != nil {
			return nil, err
		}
		return roles, nil
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedRolesCount, repo.listDeletedRoleIds, tok)
}
