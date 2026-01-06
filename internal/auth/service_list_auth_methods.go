// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListAuthMethods lists up to page size auth methods, filtering out entries that
// do not pass the filter item function. It will automatically request
// more auth methods from the database, at page size chunks, to fill the page.
// It returns a new list token used to continue pagination or refresh items.
// Auth methods are ordered by create time descending (most recently created first).
func ListAuthMethods(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[AuthMethod],
	repo *AuthMethodRepository,
	scopeIds []string,
	withUnauthenticatedUser bool,
) (*pagination.ListResponse[AuthMethod], error) {
	const op = "auth.ListAuthMethods"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case len(scopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	}

	listItemsFn := func(ctx context.Context, lastPageItem AuthMethod, limit int) ([]AuthMethod, time.Time, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if withUnauthenticatedUser {
			opts = append(opts, WithUnauthenticatedUser(ctx, true))
		}
		return repo.List(ctx, scopeIds, lastPageItem, opts...)
	}

	return pagination.List(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount)
}
