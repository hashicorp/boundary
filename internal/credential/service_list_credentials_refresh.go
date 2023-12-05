// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
)

// ListRefresh lists up to page size credentials, filtering out entries that
// do not pass the filter item function. It will automatically request
// more credentials from the database, at page size chunks, to fill the page.
// It will start its paging based on the information in the token.
// It returns a new list token used to continue pagination or refresh items.
// Credentials are ordered by update time descending (most recently updated first).
// Credentials may contain items that were already returned during the initial
// pagination phase. It also returns a list of any credentials deleted since the
// start of the initial pagination phase or last response.
func ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn pagination.ListFilterFunc[Static],
	tok *listtoken.Token,
	service CredentialService,
	credentialStoreId string,
) (*pagination.ListResponse[Static], error) {
	const op = "credential.ListRefresh"

	switch {
	case len(grantsHash) == 0:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing grants hash")
	case pageSize < 1:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "page size must be at least 1")
	case filterItemFn == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing filter item callback")
	case tok == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing token")
	case service == nil:
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing service")
	case credentialStoreId == "":
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing credential store ID")
	}
	rt, ok := tok.Subtype.(*listtoken.StartRefreshToken)
	if !ok {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "token did not have a start-refresh token component")
	}

	listItemsFn := func(ctx context.Context, lastPageItem Static, limit int) ([]Static, time.Time, error) {
		opts := []Option{
			WithLimit(limit),
		}
		if lastPageItem != nil {
			opts = append(opts, WithStartPageAfterItem(lastPageItem))
		}
		// Add the database read timeout to account for any creations missed due to concurrent
		// transactions in the initial pagination phase.
		return service.ListCredentialsRefresh(ctx, credentialStoreId, rt.PreviousPhaseUpperBound.Add(-globals.RefreshReadLookbackDuration), opts...)
	}
	listDeletedIdsFn := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Add the database read timeout to account for any deletions missed due to concurrent
		// transactions in previous requests.
		return service.ListDeletedCredentialIds(ctx, since.Add(-globals.RefreshReadLookbackDuration))
	}

	return pagination.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listItemsFn, service.EstimatedCredentialCount, listDeletedIdsFn, tok)
}
