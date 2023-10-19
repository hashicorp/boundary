// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package credential

import (
	"context"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/refreshtoken"
)

// ListRefresh lists credentials according to the page size and refresh token,
// filtering out entries that do not pass the filter item fn.
// It returns a new refresh token based on the grants hash and the returned credentials.
func ListRefresh(
	ctx context.Context,
	grantsHash []byte,
	pageSize int,
	filterItemFn ListFilterCredentialFunc,
	tok *refreshtoken.Token,
	repo Repository,
	credentialStoreId string,
) (*ListCredentialsResponse, error) {
	const op = "credential.ListRefresh"

	deletedIds, transactionTimestamp, err := repo.ListDeletedCredentialIds(ctx, tok.UpdatedTime)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	limit := pageSize + 1
	opts := []Option{
		WithLimit(limit),
		WithStartPageAfterItem(tok.ToPartialResource()),
	}

	credentials := make([]Static, 0, limit)
dbLoop:
	for {
		// Request another page from the DB until we fill the final items
		page, err := repo.ListCredentials(ctx, credentialStoreId, opts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, item := range page {
			ok, err := filterItemFn(item)
			if err != nil {
				return nil, err
			}
			if ok {
				credentials = append(credentials, item)
				// If we filled the items after filtering,
				// we're done.
				if len(credentials) == cap(credentials) {
					break dbLoop
				}
			}
		}
		// If the current page was shorter than the limit, stop iterating
		if len(page) < limit {
			break dbLoop
		}

		opts = []Option{
			WithLimit(limit),
			WithStartPageAfterItem(page[len(page)-1]),
		}
	}
	// If we couldn't fill the items, it was a complete listing.
	completeListing := len(credentials) < cap(credentials)
	if !completeListing {
		// Items is of size pageSize+1, so
		// truncate if it was filled.
		credentials = credentials[:pageSize]
	}

	totalItems, err := repo.EstimatedCredentialCount(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	resp := &ListCredentialsResponse{
		Items:               credentials,
		DeletedIds:          deletedIds,
		EstimatedTotalItems: totalItems,
		CompleteListing:     completeListing,
	}

	// Use the timestamp of the deleted IDs transaction with a
	// buffer to account for overlapping transactions. It is okay
	// to return a deleted ID more than once. The buffer corresponds
	// to Postgres' default transaction timeout.
	updatedTime := transactionTimestamp.Add(-30 * time.Second)
	if updatedTime.Before(tok.CreatedTime) {
		// Ensure updated time isn't before created time due
		// to the buffer.
		updatedTime = tok.CreatedTime
	}
	if len(credentials) > 0 {
		resp.RefreshToken = tok.RefreshLastItem(credentials[len(credentials)-1], updatedTime)
	} else {
		resp.RefreshToken = tok.Refresh(updatedTime)
	}

	return resp, nil
}
