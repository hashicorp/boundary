// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListStoresPage lists up to page size credential stores, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credential stores from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Credential stores are ordered by create time descending (most recently created first).
func ListStoresPage(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Store],
	tok *listtoken.Token,
	repo *StoreRepository,
	projectIds []string,
) (*pagination.ListResponse[Store], error) {
	const op = "credential.ListStoresPage"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case len(projectIds) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing project ids")
	case repo == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing repo")
	case tok.ResourceType != resource.CredentialStore:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a credential store resource type")
	}
	if _, ok := tok.Subtype.(*listtoken.PaginationToken); !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a pagination token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Store, limit int) ([]Store, time.Time, error) {
		if lastPageItem != nil {
			return repo.List(ctx, projectIds, lastPageItem, limit)
		}
		lastItem, err := tok.LastItem(ctx)
		if err != nil {
			return nil, time.Time{}, err
		}
		return repo.List(ctx, projectIds, lastItem, limit)
	}

	return pagination.ListPage(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount, tok)
}
