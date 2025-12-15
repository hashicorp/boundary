// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListAliasesRefresh lists up to page size aliases, filtering out entries that
// do not pass the filter item function. It will automatically request
// more aliases from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Aliases are ordered by update time descending (most recently updated first).
// Aliases may contain items that were already returned during the initial
// pagination phase. It also returns a list of any aliases deleted since the
// start of the initial pagination phase or last response.
func ListAliasesRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Alias],
	tok *listtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*Alias], error) {
	const op = "target.ListAliasesRefresh"

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
	case len(withScopeIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing scope ids")
	case tok.ResourceType != resource.Alias:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a alias resource type")
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *Alias, limit int) ([]*Alias, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.listAliasesRefresh(ctx, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), withScopeIds, opts...)
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		return repo.listDeletedIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount, listDeletedIdsFn, tok)
}

// ListResolvableAliasesRefresh lists up to page size aliases, filtering out entries that
// do not pass the filter item function. It will automatically request
// more aliases from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Aliases are ordered by update time descending (most recently updated first).
// Aliases may contain items that were already returned during the initial
// pagination phase. It also returns a list of any aliases deleted since the
// start of the initial pagination phase or last response, or which have been
// updated since that last time and do not have a destination id that is for
// a target that is included in the list of permissions.
func ListResolvableAliasesRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	tok *listtoken.Token,
	repo *Repository,
	permissions []perms.Permission,
) (*pagination.ListResponse[*Alias], error) {
	const op = "target.ListResolvableAliasesRefresh"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case tok.ResourceType != resource.Alias:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a alias resource type")
	case len(permissions) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing target permissions")
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *Alias, limit int) ([]*Alias, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.listResolvableAliasesRefresh(ctx, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), permissions, opts...)
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		return repo.listRemovedResolvableAliasIds(ctx, since.Add(-globals.RefreshReadLookbackDuration), permissions)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, alwaysTrueFilterFn, listItemsFn, repo.estimatedCount, listDeletedIdsFn, tok)
}
