// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// ListStoresRefresh lists up to page size credential stores, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credential stores from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Credential stores are ordered by update time descending (most recently updated first).
// Credential stores may contain items that were already returned during the initial
// pagination phase. It also returns a list of any credential stores deleted since the
// start of the initial pagination phase or last response.
func ListStoresRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Store],
	tok *listtoken.Token,
	repo *StoreRepository,
	projectIds []string,
) (*pagination.ListResponse[Store], error) {
	const op = "credential.ListStoresRefresh"

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
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Store, limit int) ([]Store, time.Time, error) {
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return repo.ListRefresh(ctx, projectIds, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), lastPageItem, limit)
	}
	listDeletedIDsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		since = since.Add(-globals.RefreshReadLookbackDuration)
		return repo.ListDeletedIds(ctx, since)
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, repo.EstimatedCount, listDeletedIDsFn, tok)
}
