// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListAuthMethodsPage lists up to page size auth methods, filtering out entries that
// do not pass the filter item function. It will automatically request
// more auth methods from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Auth methods are ordered by create time descending (most recently created first).
func ListAuthMethodsPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[AuthMethod],
	tok *listtoken.Token,
	repo *AuthMethodRepository,
	scopeIds []string,
	withUnauthenticatedUser bool,
) (*pagination.ListResponse[AuthMethod], error) {
	const op = "auth.ListAuthMethodsPage"

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
	case len(scopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	case tok.ResourceType != resource.AuthMethod:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have an auth method resource type")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem AuthMethod, limit int) ([]AuthMethod, time.Time, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if withUnauthenticatedUser {
			opts = append(opts, WithUnauthenticatedUser(ctx, true))
		}

		if lastPageItem != nil {
			return repo.List(ctx, scopeIds, lastPageItem, opts...)
		}
		lastItem, err := tok.LastItem(ctx)
		if err != nil {
			return nil, time.Time{}, err
		}
		return repo.List(ctx, scopeIds, lastItem, opts...)
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount, tok)
}
