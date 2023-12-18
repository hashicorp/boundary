// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package iam

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListRolesRefresh lists up to page size roles, filtering out entries that
// do not pass the filter item function. It will automatically request
// more roles from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Roles are ordered by update time descending (most recently updated first).
// Roles may contain items that were already returned during the initial
// pagination phase. It also returns a list of any roles deleted since the
// start of the initial pagination phase or last response.
func ListRolesRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Role],
	tok *listtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*Role], error) {
	const op = "iam.ListRolesRefresh"

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
	case tok.ResourceType != resource.Role:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a role resource type")
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *Role, limit int) ([]*Role, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.listRolesRefresh(ctx, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), withScopeIds, opts...)
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		return repo.listRoleDeletedIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedRoleCount, listDeletedIdsFn, tok)
}

// ListUsersRefresh lists up to page size users, filtering out entries that
// do not pass the filter item function. It will automatically request
// more users from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Users are ordered by update time descending (most recently updated first).
// Users may contain items that were already returned during the initial
// pagination phase. It also returns a list of any users deleted since the
// start of the initial pagination phase or last response.
func ListUsersRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*User],
	tok *listtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*User], error) {
	const op = "iam.ListUsersRefresh"

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
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *User, limit int) ([]*User, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.listUsersRefresh(ctx, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), withScopeIds, opts...)
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		return repo.listUserDeletedIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedUserCount, listDeletedIdsFn, tok)
}
