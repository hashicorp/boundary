// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

func List(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*AppToken],
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*AppToken], error) {
	const op = "apptoken.List"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case len(withScopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *AppToken, limit int) ([]*AppToken, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		return repo.listAppTokens(ctx, withScopeIds, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount)
}
