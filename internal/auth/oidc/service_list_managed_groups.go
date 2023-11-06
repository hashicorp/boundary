// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListManagedGroups lists managed groups according to the page size,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned managed groups.
func ListManagedGroups(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[auth.ManagedGroup],
	repo *Repository,
	authMethodId string,
) (*pagination.ListResponse[auth.ManagedGroup], error) {
	const op = "oidc.ListManagedGroups"

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
	if authMethodId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing auth method id")
	}

	listItemsFn := func(ctx context.Context, lastPageItem auth.ManagedGroup, limit int) ([]auth.ManagedGroup, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts,
				WithStartPageAfterItem(lastPageItem),
			)
		}
		mgs, err := repo.ListManagedGroups(ctx, authMethodId, opts...)
		if err != nil {
			return nil, err
		}
		var items []auth.ManagedGroup
		for _, i := range mgs {
			items = append(items, i)
		}
		return items, nil
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedManagedGroupCount)
}
