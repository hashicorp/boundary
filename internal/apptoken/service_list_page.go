// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptoken

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListPage lists up to page size app tokens, filtering out entries that
// do not pass the filter item function. It will automatically request
// more app tokens from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// App tokens are ordered by create time descending (most recently created first).
func ListPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*AppToken],
	tok *listtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*AppToken], error) {
	const op = "apptoken.ListPage"

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
	case withScopeIds == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	case tok.ResourceType != resource.AppToken:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have an app token resource type")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *AppToken, limit int) ([]*AppToken, time.Time, error) {
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
		return repo.listAppTokens(ctx, withScopeIds, opts...)
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount, tok)
}
