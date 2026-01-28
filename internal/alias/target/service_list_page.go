// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListAliasesPage lists up to page size aliases, filtering out entries that
// do not pass the filter item function. It will automatically request
// more aliases from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Aliases are ordered by create time descending (most recently created first).
func ListAliasesPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[*Alias],
	tok *listtoken.Token,
	repo *Repository,
	withScopeIds []string,
) (*pagination.ListResponse[*Alias], error) {
	const op = "target.ListAliasesPage"

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
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *Alias, limit int) ([]*Alias, time.Time, error) {
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
		return repo.listAliases(ctx, withScopeIds, opts...)
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.estimatedCount, tok)
}

// ListResolvableAliasesPage lists up to page size aliases, filtering out entries that
// do not pass the filter item function. It will automatically request
// more aliases from the database, at page size chunks, to fill the page.
// Only aliases which resolve to a target for which there are permissions in the
// included slice of permissions are returned.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Aliases are ordered by create time descending (most recently created first).
func ListResolvableAliasesPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	tok *listtoken.Token,
	repo *Repository,
	perms []perms.Permission,
) (*pagination.ListResponse[*Alias], error) {
	const op = "target.ListResolvableAliasesPage"

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
	case len(perms) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing permissions")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem *Alias, limit int) ([]*Alias, time.Time, error) {
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
		return repo.listResolvableAliases(ctx, perms, opts...)
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, alwaysTrueFilterFn, listItemsFn, repo.estimatedCount, tok)
}
