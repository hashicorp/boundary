// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListAliases lists up to page size aliases, filtering out entries that
// do not pass the filter item function. It will automatically request
// more aliases from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Aliases are ordered by create time descending (most recently created first).
func ListAliases(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Alias],
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*Alias], error) {
	const op = "target.ListAliases"

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

	listItemsFn := func(ctx context.Context, lastPageItem *Alias, limit int) ([]*Alias, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		return repo.listAliases(ctx, withScopeIds, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount)
}
