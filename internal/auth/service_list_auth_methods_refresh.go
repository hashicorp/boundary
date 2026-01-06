// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListAuthMethodsRefresh lists up to page size auth methods, filtering out entries that
// do not pass the filter item function. It will automatically request
// more auth methods from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Auth methods are ordered by update time descending (most recently updated first).
// Auth methods may contain items that were already returned during the initial
// pagination phase. It also returns a list of any auth methods deleted since the
// start of the initial pagination phase or last response.
func ListAuthMethodsRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[AuthMethod],
	tok *listtoken.Token,
	repo *AuthMethodRepository,
	scopeIds []string,
	withUnauthenticatedUser bool,
) (*pagination.ListResponse[AuthMethod], error) {
	const op = "auth.ListAuthMethodsRefresh"

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
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem AuthMethod, limit int) ([]AuthMethod, time.Time, error) {
		opts := []Option{
			WithLimit(ctx, limit),
		}
		if withUnauthenticatedUser {
			opts = append(opts, WithUnauthenticatedUser(ctx, true))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.ListRefresh(ctx, scopeIds, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), lastPageItem, opts...)
	}
	listDeletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		since = since.Add(-globals.RefreshReadLookbackDuration)
		return repo.ListDeletedIds(ctx, since)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount, listDeletedIDsFn, tok)
}
